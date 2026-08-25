package transmit

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

// buildHTTPClient constructs the transport from the options.
//
// http.ProxyFromEnvironment is deliberate rather than incidental: HTTP_PROXY,
// HTTPS_PROXY and NO_PROXY are how every other agent on a managed estate is
// pointed at the egress path, and a collector that ignored them would be the
// one thing an operator has to special-case in the firewall.
func buildHTTPClient(opts Options) (*http.Client, error) {
	tlsCfg := &tls.Config{
		// TLS 1.2 floor: the server contract is HTTPS and anything below this
		// has no business carrying an inventory of a machine's software.
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: opts.InsecureSkipVerify, // #nosec G402 -- opt-in, and refused unless asked for
	}

	if opts.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.ClientCertFile, opts.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("transmit: loading the client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile) // #nosec G304 -- operator-supplied path, by design
		if err != nil {
			return nil, fmt.Errorf("transmit: reading the CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			// AppendCertsFromPEM reports failure by returning false and
			// nothing else. Left unchecked, a CA file with a stray header or
			// a DER blob inside produces an empty pool and every connection
			// fails with an unrelated-looking verification error.
			return nil, fmt.Errorf("transmit: %s contains no PEM certificates", opts.CAFile)
		}
		tlsCfg.RootCAs = pool
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		// One host, many sequential requests: keeping the connection warm is
		// the difference between one TLS handshake per scan and one per batch.
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}

	// No client-level timeout: it would bound the whole upload rather than one
	// request, and a large scan on a slow link is not an error. Each request
	// gets its own deadline in do().
	return &http.Client{Transport: transport}, nil
}

// gzipBytes compresses a batch body.
//
// Measured about 9:1 on this data. That saves nothing on wall clock and a
// great deal on a metered link, which is the situation a collector on a
// branch-office box is actually in.
func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, fmt.Errorf("transmit: compressing the batch: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("transmit: finishing the compressed batch: %w", err)
	}
	return buf.Bytes(), nil
}

// PermanentError marks a failure that retrying cannot fix.
//
// The distinction is the whole of the retry policy. A 401 retried five times
// is five identical rejections and a collector that reports "network trouble"
// for a token nobody renewed; a 503 not retried at all is a scan lost to a
// rolling restart.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

func permanent(err error) error { return &PermanentError{Err: err} }

// IsPermanent reports whether err is one nothing will fix.
func IsPermanent(err error) bool {
	var p *PermanentError
	return errors.As(err, &p)
}

// classify turns an HTTP response into nil, a retryable error, or a permanent
// one.
//
// 429 is the exception that proves the rule: it is a 4xx, so by status class
// it is the client's fault, but it is the one 4xx that says "later" rather
// than "no". Treating it as permanent would make a rate-limited fleet give up
// in unison.
func classify(resp *http.Response, body []byte) error {
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil

	case resp.StatusCode == http.StatusTooManyRequests:
		return &retryAfterError{
			after: parseRetryAfter(resp.Header.Get("Retry-After")),
			err:   fmt.Errorf("HTTP 429 from the server: %s", truncate(body)),
		}

	case resp.StatusCode == http.StatusConflict:
		// The reconciliation verdict. The server compared what the manifest
		// declared against what it stored and they disagree, which is a fact
		// about the data and not about the connection. Retrying re-sends
		// identical bytes and gets an identical answer.
		return permanent(fmt.Errorf("HTTP 409: the server's count disagrees with the manifest: %s",
			truncate(body)))

	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return permanent(fmt.Errorf("HTTP %d from the server: %s", resp.StatusCode, truncate(body)))

	default:
		return fmt.Errorf("HTTP %d from the server: %s", resp.StatusCode, truncate(body))
	}
}

// retryAfterError carries a server-specified delay.
type retryAfterError struct {
	after time.Duration
	err   error
}

func (e *retryAfterError) Error() string { return e.err.Error() }
func (e *retryAfterError) Unwrap() error { return e.err }

// parseRetryAfter reads the delay-seconds form of Retry-After. The HTTP-date
// form is ignored on purpose: it depends on the two clocks agreeing, and a
// collector's clock being wrong is common enough that honouring it could sleep
// for hours.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	const cap = 5 * time.Minute
	d := time.Duration(n) * time.Second
	if d > cap {
		return cap
	}
	return d
}

// retryBase is the first backoff interval; each attempt doubles it.
const retryBase = 500 * time.Millisecond

// retryMax caps one wait, so a long attempt budget cannot turn into a sleep
// measured in minutes.
const retryMax = 8 * time.Second

// retry runs fn until it succeeds, exhausts attempts, or fails permanently.
//
// The jitter is not decoration. A fleet of collectors driven by the same
// systemd timer retries in lockstep without it, and the synchronised second
// attempt lands on a server that is still recovering from the first.
func retry(ctx context.Context, attempts int, logf func(string, ...any), fn func(attempt int) error) error {
	var last error
	for attempt := 1; attempt <= attempts; attempt++ {
		err := fn(attempt)
		if err == nil {
			return nil
		}
		if IsPermanent(err) {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			// The whole-run deadline, not this request's. Report the reason
			// the work stopped rather than the symptom it produced.
			return fmt.Errorf("%w (last error: %w)", ctxErr, err)
		}
		last = err
		if attempt == attempts {
			break
		}

		wait := backoff(attempt)
		var ra *retryAfterError
		if errors.As(err, &ra) && ra.after > wait {
			wait = ra.after
		}
		logf("transmit: attempt %d failed (%v); retrying in %s", attempt, err, wait.Round(time.Millisecond))

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("%w (last error: %w)", ctx.Err(), err)
		case <-timer.C:
		}
	}
	return fmt.Errorf("gave up after %d attempts: %w", attempts, last)
}

// backoff is exponential with full jitter over the interval.
func backoff(attempt int) time.Duration {
	d := retryBase << (attempt - 1)
	if d > retryMax || d <= 0 {
		d = retryMax
	}
	// Full jitter: uniform over [d/2, d]. Half the interval is kept as a floor
	// so a retry storm cannot collapse into an immediate re-send.
	half := d / 2
	// #nosec G404 -- jitter spreads a fleet's retries; it is not a secret
	return half + time.Duration(rand.Int64N(int64(half)+1))
}
