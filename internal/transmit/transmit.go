// Package transmit posts a scan's NDJSON to a Riskability server.
//
// It is the client half of docs/API.md in the riskability-server repository:
// open a scan with its manifest, push the records as numbered batches, close
// it and read the reconciliation verdict back. Everything here exists because
// of one property of that contract -- the server compares what the manifest
// declared against what it stored, and disagreement is an error rather than a
// warning field. This package's job is to make sure a disagreement means the
// data really is missing, and never that the transport lost it quietly.
//
// File output is not a fallback for this and this is not a replacement for
// file output. Air-gapped estates are the likeliest audience for the product
// and they move files by means they already trust; a site that can reach a
// server gets both.
package transmit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Defaults for the tunables. They are exported so the flag layer states the
// same numbers the help page prints.
const (
	// DefaultBatchLines is a compromise between request count and blast
	// radius. A 15,000-component host becomes eight requests; a batch that
	// fails and cannot be retried loses at most this many records, and the
	// server names the batch index in its status so the loss is identifiable
	// rather than a hole somewhere in the middle.
	DefaultBatchLines = 2000

	// DefaultBatchBytes bounds the request body before compression. Whichever
	// of the two limits trips first ends the batch: line count alone is not
	// enough, because a host with large attribute maps can put 2,000 lines
	// well past any sane body limit, and a 4 MB scan in one request is the
	// specific thing this exists to prevent.
	DefaultBatchBytes = 1 << 20

	// DefaultAttempts counts the first try. Five attempts with the backoff
	// below spans roughly half a minute, which covers a rolling restart of the
	// server without covering an outage long enough that the collector should
	// simply give up and leave the spool for the next run.
	DefaultAttempts = 5

	// DefaultRequestTimeout bounds one HTTP request, not the whole upload.
	DefaultRequestTimeout = 60 * time.Second
)

// Options configures one client.
type Options struct {
	// BaseURL is the server's API root, e.g. https://riskability.example/api/v1.
	// A trailing /ingest is added; a BaseURL that already ends in /ingest is
	// accepted too, because that is the URL an operator is most likely to be
	// given.
	BaseURL string

	// Token is the bearer token, if the estate distributes tokens.
	Token string

	// ClientCertFile and ClientKeyFile are the client certificate, if the
	// estate runs a CA instead. Both mechanisms are supported and both may be
	// configured at once: some servers require the certificate for transport
	// and the token for the account it maps to.
	ClientCertFile string
	ClientKeyFile  string

	// KeyPassphrase decrypts ClientKeyFile when the estate hands out
	// passphrase-protected keys, which any estate running a CA does.
	KeyPassphrase []byte

	// CAFile is a PEM bundle to verify the server against, for an internal CA
	// that is not in the system trust store.
	CAFile string

	// Pins verifies the server by public key instead of by chain: each entry
	// is the base64 SHA-256 of a SubjectPublicKeyInfo. Repeatable so a key
	// rotation is two pins for a while rather than a flag day. Mutually
	// exclusive with InsecureSkipVerify.
	Pins []string

	// TLSMinVersion raises the TLS floor. Zero means 1.2; there is no value
	// that lowers it.
	TLSMinVersion uint16

	// InsecureSkipVerify disables server certificate verification. It exists
	// for a first-day trial against a self-signed endpoint and is loud
	// everywhere it appears.
	InsecureSkipVerify bool

	// Compress controls the request bodies: "auto" (the default - gzip when
	// it helps), "always", or "never". "never" exists to diagnose the proxy
	// or WAF that mangles gzipped bodies, a real failure mode that is
	// miserable to chase when compression cannot be turned off.
	Compress string

	// RateLimitBytesPerSec caps upload throughput for metered links.
	// Zero is unlimited.
	RateLimitBytesPerSec int64

	BatchLines     int
	BatchBytes     int
	Attempts       int
	RequestTimeout time.Duration

	// HTTPClient overrides the constructed client. Tests set it; nothing else
	// should need to.
	HTTPClient *http.Client

	// Logf receives progress. Never nil after New.
	Logf func(string, ...any)
}

// Client posts scans to one server.
type Client struct {
	opts Options
	http *http.Client
	base string
}

// New builds a client and validates everything that can be validated without
// touching the network.
//
// Configuration errors surface here rather than after a multi-minute scan: a
// typo in a certificate path that only appears at upload time costs the whole
// scan, and it is the sort of mistake that is made once and repeated hourly by
// a timer.
func New(opts Options) (*Client, error) {
	base, err := normalizeBase(opts.BaseURL)
	if err != nil {
		return nil, err
	}
	if opts.BatchLines <= 0 {
		opts.BatchLines = DefaultBatchLines
	}
	if opts.BatchBytes <= 0 {
		opts.BatchBytes = DefaultBatchBytes
	}
	if opts.Attempts <= 0 {
		opts.Attempts = DefaultAttempts
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = DefaultRequestTimeout
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if (opts.ClientCertFile == "") != (opts.ClientKeyFile == "") {
		return nil, fmt.Errorf("transmit: a client certificate needs both the certificate and its key")
	}
	if opts.Token == "" && opts.ClientCertFile == "" {
		return nil, fmt.Errorf("transmit: no credentials; supply a bearer token or a client certificate")
	}
	if len(opts.Pins) > 0 && opts.InsecureSkipVerify {
		// An error, not a precedence rule: whichever one the operator meant,
		// the other one in the unit file is a mistake worth stopping for.
		return nil, fmt.Errorf("transmit: a pinned key and --transmit-insecure contradict each other; remove one")
	}
	switch opts.Compress {
	case "", "auto", "always", "never":
	default:
		return nil, fmt.Errorf("transmit: compress mode %q is not auto, always or never", opts.Compress)
	}

	hc := opts.HTTPClient
	if hc == nil {
		hc, err = buildHTTPClient(opts)
		if err != nil {
			return nil, err
		}
	}
	return &Client{opts: opts, http: hc, base: base}, nil
}

// normalizeBase turns whatever the operator typed into the /ingest root.
func normalizeBase(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("transmit: empty server URL")
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return "", fmt.Errorf("transmit: %q has no scheme; use https://host/api/v1", raw)
	}
	s = strings.TrimRight(s, "/")
	if !strings.HasSuffix(s, "/ingest") {
		s += "/ingest"
	}
	return s, nil
}

// openResponse is what POST /ingest/scan answers.
type openResponse struct {
	ScanID string `json:"scan_id"`
	// ResumeFrom is the first batch index the server still needs. A server
	// that has never seen this scan answers 0.
	ResumeFrom int `json:"resume_from"`
}

// statusResponse is what GET /ingest/scan/{id}/status answers.
type statusResponse struct {
	ScanID     string `json:"scan_id"`
	ResumeFrom int    `json:"resume_from"`
	Received   int    `json:"records_received"`
}

// CloseVerdict is the reconciliation the server returns from close.
//
// A mismatch arrives as HTTP 409 with these two numbers, which is the reason
// the manifest exists at all. It is surfaced verbatim rather than summarised:
// "declared 3993, stored 15" is the sentence that would have ended a day of
// debugging in its first minute.
type CloseVerdict struct {
	ScanID     string `json:"scan_id"`
	Declared   int    `json:"declared_components"`
	Stored     int    `json:"stored_components"`
	Reconciled bool   `json:"reconciled"`
	Message    string `json:"message"`
}

// Send uploads one spooled scan and returns the server's verdict.
//
// The spool is the unit of resumption: it holds the exact bytes that were
// declared, so a run that dies half way up can be finished by a later one
// without rescanning the machine and without the counts shifting underneath
// the manifest.
func (c *Client) Send(ctx context.Context, sp *Spool) (*CloseVerdict, error) {
	manifest, err := sp.Manifest()
	if err != nil {
		return nil, err
	}

	scanID := sp.State().ScanID

	// Open (or re-open) the scan. Idempotent by contract: a scan already open
	// answers with where it wants us to resume, which is how a server restart
	// mid-scan costs a few duplicate batches rather than the whole upload.
	open, err := c.openScan(ctx, manifest)
	if err != nil {
		return nil, err
	}
	if open.ScanID != "" && open.ScanID != scanID {
		// The server is entitled to mint its own identifier. Follow it, and
		// record it, or every resume afterwards would address a scan the
		// server has never heard of.
		scanID = open.ScanID
		if err := sp.SetScanID(scanID); err != nil {
			return nil, err
		}
	}
	start := open.ResumeFrom

	// Ask explicitly where to resume when the local state believes work was
	// already done. The server's answer wins: it is the only party that knows
	// what it stored, and re-sending a batch it already has is free because
	// (scan_id, batch_index) is idempotent, while skipping one it never got is
	// a silent hole.
	if sp.State().Acked > 0 {
		st, err := c.status(ctx, scanID)
		if err != nil {
			return nil, err
		}
		start = st.ResumeFrom
		c.opts.Logf("transmit: resuming %s at batch %d (server holds %d record(s))",
			shortID(scanID), start, st.Received)
	}

	sent := 0
	err = sp.EachBatch(func(index int, body []byte, lines int) error {
		if index < start {
			return nil
		}
		if err := c.postBatch(ctx, scanID, index, body); err != nil {
			return err
		}
		sent += lines
		// Recorded after the server acknowledged it, never before. A state
		// file that runs ahead of the server is exactly how a resume skips a
		// batch nobody ever stored.
		return sp.Ack(index)
	})
	if err != nil {
		return nil, err
	}

	verdict, err := c.closeScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	c.opts.Logf("transmit: sent %d record(s) in scan %s; server stored %d of %d declared",
		sent, shortID(scanID), verdict.Stored, verdict.Declared)
	return verdict, nil
}

// Endpoint is the /ingest root this client posts to. It is what a spool
// records, so a backlog can be matched to the server it was collected for.
func (c *Client) Endpoint() string { return c.base }

func (c *Client) openScan(ctx context.Context, manifest []byte) (*openResponse, error) {
	var out openResponse
	err := c.do(ctx, http.MethodPost, c.base+"/scan", "", manifest, false, &out)
	if err != nil {
		return nil, fmt.Errorf("opening the scan: %w", err)
	}
	return &out, nil
}

func (c *Client) status(ctx context.Context, scanID string) (*statusResponse, error) {
	var out statusResponse
	err := c.do(ctx, http.MethodGet, c.base+"/scan/"+scanID+"/status", scanID, nil, false, &out)
	if err != nil {
		return nil, fmt.Errorf("asking where to resume: %w", err)
	}
	return &out, nil
}

func (c *Client) postBatch(ctx context.Context, scanID string, index int, body []byte) error {
	url := c.base + "/scan/" + scanID + "/batch/" + strconv.Itoa(index)
	if err := c.do(ctx, http.MethodPost, url, scanID, body, true, nil); err != nil {
		return fmt.Errorf("batch %d: %w", index, err)
	}
	return nil
}

func (c *Client) closeScan(ctx context.Context, scanID string) (*CloseVerdict, error) {
	var out CloseVerdict
	err := c.do(ctx, http.MethodPost, c.base+"/scan/"+scanID+"/close", scanID, []byte("{}"), false, &out)
	if err != nil {
		return nil, fmt.Errorf("closing the scan: %w", err)
	}
	if out.ScanID == "" {
		out.ScanID = scanID
	}
	return &out, nil
}

// do performs one request with retries, and decodes into out when out is
// non-nil.
func (c *Client) do(ctx context.Context, method, url, scanID string, body []byte, gzipBody bool, out any) error {
	payload := body
	encoding := ""
	if gzipBody && len(body) > 0 && c.opts.Compress != "never" {
		compressed, err := gzipBytes(body)
		if err != nil {
			return err
		}
		// Auto compresses only when it actually helps. It always does on this
		// data -- NDJSON of package records compresses about 9:1 -- but a
		// batch that grew under compression would be a strange thing to
		// insist on. "always" insists anyway, for the operator who wants the
		// unit file to state what is on the wire.
		if len(compressed) < len(body) || c.opts.Compress == "always" {
			payload, encoding = compressed, "gzip"
		}
	}

	return retry(ctx, c.opts.Attempts, c.opts.Logf, func(attempt int) error {
		timeout := c.opts.RequestTimeout
		if c.opts.RateLimitBytesPerSec > 0 && payload != nil {
			// A deliberately slow upload must not trip the per-request
			// deadline that assumes full speed. Twice the paced duration,
			// floored at the normal timeout, keeps the deadline meaningful.
			paced := time.Duration(int64(len(payload))*int64(time.Second)/c.opts.RateLimitBytesPerSec) * 2
			if paced > timeout {
				timeout = paced
			}
		}
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		var rdr io.Reader
		if payload != nil {
			rdr = bytes.NewReader(payload)
			if c.opts.RateLimitBytesPerSec > 0 {
				rdr = &throttledReader{r: rdr, bps: c.opts.RateLimitBytesPerSec, ctx: reqCtx}
			}
		}
		req, err := http.NewRequestWithContext(reqCtx, method, url, rdr)
		if err != nil {
			// A malformed URL will not become well-formed on the next attempt.
			return permanent(fmt.Errorf("building request: %w", err))
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/x-ndjson")
			req.ContentLength = int64(len(payload))
		}
		if encoding != "" {
			req.Header.Set("Content-Encoding", encoding)
		}
		if c.opts.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.opts.Token)
		}
		if scanID != "" {
			// The scan id is already in the path for batches. It is sent as a
			// header as well because that is the field a server, a proxy or an
			// audit log looks for, and because the open and close calls have
			// no batch index to key on.
			req.Header.Set("Idempotency-Key", scanID)
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := c.http.Do(req)
		if err != nil {
			// Network-level failures are the retryable case by definition:
			// nothing is known about whether the server saw the request, and
			// re-sending is safe because every endpoint here is idempotent.
			return fmt.Errorf("attempt %d: %w", attempt, err)
		}
		defer func() { _ = resp.Body.Close() }()

		// Read the body before branching. An error body is the only place the
		// server explains itself, and discarding it is how a permanent failure
		// becomes "HTTP 400" with no way to act on it.
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

		if err := classify(resp, respBody); err != nil {
			return err
		}
		if readErr != nil {
			return fmt.Errorf("reading the response: %w", readErr)
		}
		if out != nil && len(bytes.TrimSpace(respBody)) > 0 {
			if err := json.Unmarshal(respBody, out); err != nil {
				return permanent(fmt.Errorf("the server's reply is not JSON: %w (body: %s)",
					err, truncate(respBody)))
			}
		}
		return nil
	})
}

// maxResponseBytes caps what is read back. The server's replies are receipts
// and verdicts; anything larger is a captive portal or a proxy error page, and
// buffering it whole helps nobody.
const maxResponseBytes = 64 << 10

// userAgent identifies the collector in the server's access log, which is
// where a fleet-wide version skew is first noticed.
const userAgent = "swinv-transmit/1"

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func truncate(b []byte) string {
	const max = 300
	s := strings.TrimSpace(string(b))
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
