package transmit

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CheckResult is one line of the preflight report.
type CheckResult struct {
	Name   string
	OK     bool
	Detail string
}

// Check validates the endpoint, authentication, TLS and clock without
// scanning or sending anything.
//
// This is the flag that makes a rollout debuggable: without it, diagnosing a
// broken deployment means running a full scan to find out the token was
// wrong. The status endpoint of a scan that does not exist is the probe - a
// 404 proves the server answered and the credentials were accepted, while a
// 401 or 403 names the actual problem. One attempt, no retries: a preflight
// that retries for half a minute answers slower than it has to.
func (c *Client) Check(ctx context.Context) []CheckResult {
	var out []CheckResult
	add := func(name string, ok bool, format string, a ...any) {
		out = append(out, CheckResult{Name: name, OK: ok, Detail: fmt.Sprintf(format, a...)})
	}

	add("endpoint", true, "%s", c.base)

	probe, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+"/scan/swinv-preflight/status", nil)
	if err != nil {
		add("reachable", false, "%v", err)
		return out
	}
	if proxyURL, perr := http.ProxyFromEnvironment(probe); perr == nil {
		if proxyURL != nil {
			add("proxy", true, "via %s", proxyURL.Redacted())
		} else {
			add("proxy", true, "direct connection")
		}
	}
	if c.opts.Token != "" {
		probe.Header.Set("Authorization", "Bearer "+c.opts.Token)
	}
	probe.Header.Set("User-Agent", userAgent)

	reqCtx, cancel := context.WithTimeout(ctx, c.opts.RequestTimeout)
	defer cancel()
	sent := time.Now()
	resp, err := c.http.Do(probe.WithContext(reqCtx))
	if err != nil {
		add("reachable", false, "%v", err)
		return out
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

	add("reachable", true, "answered HTTP %d in %s", resp.StatusCode,
		time.Since(sent).Round(time.Millisecond))

	c.checkTLS(resp, add)

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		add("auth", false, "the server rejected the credentials (HTTP %d): %s",
			resp.StatusCode, truncate(body))
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusOK:
		// 404 is the expected answer: the scan id does not exist, which means
		// the request got through authentication and routing to say so.
		add("auth", true, "credentials accepted")
	case resp.StatusCode >= 500:
		add("server", false, "HTTP %d: %s", resp.StatusCode, truncate(body))
	default:
		add("server", false, "unexpected HTTP %d for a status probe: %s", resp.StatusCode, truncate(body))
	}

	if server := resp.Header.Get("Server"); server != "" {
		add("server-version", true, "%s", server)
	}

	// Clock skew matters because tokens and certificates both expire by the
	// clock, and a host that is an hour wrong fails in ways that look like
	// anything but the clock.
	if date := resp.Header.Get("Date"); date != "" {
		if serverTime, perr := http.ParseTime(date); perr == nil {
			skew := time.Since(serverTime).Round(time.Second)
			if skew < 0 {
				skew = -skew
			}
			const tolerable = 5 * time.Minute
			add("clock", skew <= tolerable, "skew %s against the server", skew)
		}
	}
	return out
}

// checkTLS reports what the connection actually negotiated.
func (c *Client) checkTLS(resp *http.Response, add func(string, bool, string, ...any)) {
	state := resp.TLS
	if state == nil {
		add("tls", false, "the connection is not TLS; an inventory does not travel in cleartext")
		return
	}
	add("tls", true, "%s, %s", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite))

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
		add("certificate", daysLeft > 0, "%s, expires %s (%d day(s)), spki pin %s",
			leaf.Subject, leaf.NotAfter.Format("2006-01-02"), daysLeft, SPKIPin(leaf))
	}
	switch {
	case len(c.opts.Pins) > 0:
		// The handshake succeeded, so the pin verifier accepted the chain.
		add("verification", true, "pinned key matched")
	case c.opts.InsecureSkipVerify:
		add("verification", false, "DISABLED by --transmit-insecure")
	default:
		add("verification", true, "certificate chain validated")
	}
}
