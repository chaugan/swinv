package transmit

import (
	"context"
	"testing"
	"time"
)

// "never" exists to diagnose the proxy that mangles gzipped bodies; when it
// is set, no body may be compressed no matter how well it would compress.
func TestCompressNeverSendsPlainBodies(t *testing.T) {
	f := newFakeServer(t)
	c := clientFor(t, f, Options{Compress: "never"})
	sp := spoolIn(t, c, t.TempDir(), payload(200, ""))

	if _, err := c.Send(context.Background(), sp); err != nil {
		t.Fatalf("Send: %v", err)
	}
	for i, gz := range f.Gzipped {
		if gz {
			t.Errorf("batch %d was gzipped under --transmit-compress never", i)
		}
	}
}

// "always" compresses even a body that grows for it, so the unit file states
// what is on the wire and the statement is true.
func TestCompressAlwaysCompressesEvenTinyBodies(t *testing.T) {
	f := newFakeServer(t)
	c := clientFor(t, f, Options{Compress: "always", BatchLines: 1})
	sp := spoolIn(t, c, t.TempDir(), payload(1, ""))

	if _, err := c.Send(context.Background(), sp); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.Gzipped) == 0 {
		t.Fatal("no batches arrived")
	}
	for i, gz := range f.Gzipped {
		if !gz {
			t.Errorf("batch %d was not gzipped under --transmit-compress always", i)
		}
	}
}

func TestCompressRejectsJunkMode(t *testing.T) {
	if _, err := New(Options{BaseURL: "https://x/api/v1", Token: "t", Compress: "sometimes"}); err == nil {
		t.Error("compress mode 'sometimes' was accepted")
	}
}

// The throttle paces a payload to its byte rate. 4 KiB at 16 KiB/s is a
// quarter second; anything under a tenth of that means the limiter did
// nothing at all. Generous bounds, because CI machines are slow, not fast.
func TestRateLimitActuallyPaces(t *testing.T) {
	f := newFakeServer(t)
	c := clientFor(t, f, Options{
		Compress:             "never",
		RateLimitBytesPerSec: 16 << 10,
		BatchLines:           10000,
		BatchBytes:           1 << 20,
	})
	sp := spoolIn(t, c, t.TempDir(), payload(64, pad(60)))

	start := time.Now()
	if _, err := c.Send(context.Background(), sp); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("a rate-limited upload of ~4KiB at 16KiB/s finished in %s; the limiter did nothing", elapsed)
	}
}

func pad(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}
