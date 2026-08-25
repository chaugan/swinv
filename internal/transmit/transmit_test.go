package transmit

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func clientFor(t *testing.T, f *fakeServer, opts Options) *Client {
	t.Helper()
	opts.BaseURL = f.baseURL()
	if opts.Token == "" && opts.ClientCertFile == "" {
		opts.Token = "s3cret"
	}
	opts.HTTPClient = f.Client()
	opts.Logf = t.Logf
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func spoolIn(t *testing.T, c *Client, dir, body string) *Spool {
	t.Helper()
	sp, err := c.NewSpool(dir, "test-scan", "web01", 0, 0o600, 0o700, func(w io.Writer) error {
		_, err := io.WriteString(w, body)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

// TestSendUploadsEveryRecordAndReconciles is the whole contract in one pass.
func TestSendUploadsEveryRecordAndReconciles(t *testing.T) {
	f := newFakeServer(t)
	c := clientFor(t, f, Options{BatchLines: 7, BatchBytes: 1 << 20})
	sp := spoolIn(t, c, t.TempDir(), payload(30, ""))

	verdict, err := c.Send(context.Background(), sp)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !verdict.Reconciled {
		t.Errorf("verdict = %+v, want reconciled", verdict)
	}
	if got := f.storedComponents(); got != 30 {
		t.Errorf("the server stored %d components, the collector declared 30", got)
	}
	if len(f.Batches) != 5 {
		t.Errorf("got %d batches, want 5 (30 records at 7 per request)", len(f.Batches))
	}
	if !f.Closed {
		t.Error("the scan was never closed, so the server never reconciled it")
	}
	for _, a := range f.Auth {
		if a != "Bearer s3cret" {
			t.Errorf("Authorization = %q, want the bearer token on every request", a)
		}
	}
}

// TestBodiesAreGzippedAndSurviveTheRoundTrip. Roughly 9:1 on this data, and
// what arrives has to be byte-identical to what was spooled.
func TestBodiesAreGzippedAndSurviveTheRoundTrip(t *testing.T) {
	f := newFakeServer(t)
	c := clientFor(t, f, Options{BatchLines: 1000, BatchBytes: 1 << 20})
	body := payload(200, "")
	sp := spoolIn(t, c, t.TempDir(), body)

	if _, err := c.Send(context.Background(), sp); err != nil {
		t.Fatalf("Send: %v", err)
	}
	for i, gz := range f.Gzipped {
		if !gz {
			t.Errorf("batch %d was sent uncompressed", i)
		}
	}

	// The decompressed lines must be exactly the payload's record lines, in
	// order, manifest excluded.
	var got []string
	for i := 0; i < len(f.Batches); i++ {
		got = append(got, f.Batches[i]...)
	}
	want := strings.Split(strings.TrimRight(body, "\n"), "\n")[1:]
	if len(got) != len(want) {
		t.Fatalf("received %d lines, sent %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d changed in transit:\n got %s\nwant %s", i, got[i], want[i])
		}
	}
}

// TestResumeAfterAMidUploadFailure. The collector dies at batch 2; a later run
// picks the spool up and finishes it without rescanning the machine.
func TestResumeAfterAMidUploadFailure(t *testing.T) {
	f := newFakeServer(t)
	dir := t.TempDir()
	c := clientFor(t, f, Options{BatchLines: 5, BatchBytes: 1 << 20, Attempts: 1})
	sp := spoolIn(t, c, dir, payload(30, ""))

	// Batch 2 fails permanently for this run: six attempts is more than the
	// single attempt configured, so Send gives up half way.
	f.failBatchTimes(2, 503, 6)
	if _, err := c.Send(context.Background(), sp); err == nil {
		t.Fatal("Send reported success while batch 2 was failing")
	}

	if got := f.resumeFrom(); got != 2 {
		t.Fatalf("server resume point = %d, want 2", got)
	}
	stored := f.storedComponents()
	if stored != 10 {
		t.Fatalf("the server stored %d records before the failure, want 10", stored)
	}

	// A later process. Nothing is carried over in memory: the spool on disk is
	// the entire state.
	pending, err := Pending(dir, c.base)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("Pending found %d spools, want the unfinished one", len(pending))
	}
	if got := pending[0].State().Acked; got != 2 {
		t.Errorf("the reloaded spool believes %d batches were acknowledged, want 2", got)
	}

	f.failBatchTimes(-1, 0, 0)
	verdict, err := c.Send(context.Background(), pending[0])
	if err != nil {
		t.Fatalf("resumed Send: %v", err)
	}
	if !verdict.Reconciled || f.storedComponents() != 30 {
		t.Errorf("after resuming, the server holds %d of 30 records (%+v)", f.storedComponents(), verdict)
	}
	// Batches 0 and 1 were already stored and must not have been sent again:
	// resumption is the point, and re-sending the whole scan is what it
	// replaces.
	for _, i := range []int{0, 1} {
		if f.Deliveries[i] != 1 {
			t.Errorf("batch %d was delivered %d times; the resume re-sent data the server already had",
				i, f.Deliveries[i])
		}
	}
}

// TestRetriedBatchIsStoredOnce. The idempotency key's whole job: a retry after
// a timeout must not double-count a host.
func TestRetriedBatchIsStoredOnce(t *testing.T) {
	f := newFakeServer(t)
	c := clientFor(t, f, Options{BatchLines: 10, BatchBytes: 1 << 20, Attempts: 4})
	sp := spoolIn(t, c, t.TempDir(), payload(20, ""))

	// Batch 1 fails twice with a retryable status, then succeeds.
	f.failBatchTimes(1, 503, 2)

	verdict, err := c.Send(context.Background(), sp)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !verdict.Reconciled {
		t.Errorf("verdict = %+v", verdict)
	}
	if got := f.storedComponents(); got != 20 {
		t.Errorf("the server stored %d components after a retry, want 20", got)
	}
	if f.Deliveries[1] != 1 {
		t.Errorf("batch 1 was stored %d times: the retry double-counted", f.Deliveries[1])
	}
}

// TestSendingTheSameScanTwiceStoresItOnce. A whole scan replayed -- an
// operator re-running after a timeout, a spool that was never cleaned up --
// leaves the server holding one copy.
func TestSendingTheSameScanTwiceStoresItOnce(t *testing.T) {
	f := newFakeServer(t)
	c := clientFor(t, f, Options{BatchLines: 6, BatchBytes: 1 << 20})
	dir := t.TempDir()

	sp := spoolIn(t, c, dir, payload(18, ""))
	if _, err := c.Send(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	// A second spool of the same scan: same scan_id, same bytes.
	again := spoolIn(t, c, t.TempDir(), payload(18, ""))
	if _, err := c.Send(context.Background(), again); err != nil {
		t.Fatal(err)
	}

	if got := f.storedComponents(); got != 18 {
		t.Errorf("after sending the same scan twice the server holds %d components, want 18", got)
	}
}

// TestPermanentFailuresAreNotRetried. A rejected token retried five times is
// five identical rejections and a collector reporting "network trouble".
func TestPermanentFailuresAreNotRetried(t *testing.T) {
	f := newFakeServer(t)
	c := clientFor(t, f, Options{BatchLines: 5, BatchBytes: 1 << 20, Attempts: 5})
	sp := spoolIn(t, c, t.TempDir(), payload(10, ""))

	f.failBatchTimes(0, 401, 99)
	start := time.Now()
	_, err := c.Send(context.Background(), sp)
	if err == nil {
		t.Fatal("a 401 was reported as success")
	}
	if !IsPermanent(err) {
		t.Errorf("a 401 was classified as retryable: %v", err)
	}
	if f.Deliveries[0] != 0 && f.Deliveries[0] != 1 {
		t.Errorf("batch 0 was attempted %d times", f.Deliveries[0])
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("a permanent failure took %s; it was backed off as though it might recover", elapsed)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("the error does not name the status: %v", err)
	}
}

// TestRateLimitingIsRetried. 429 is the one 4xx that says "later" rather than
// "no"; treating it as permanent makes a throttled fleet give up in unison.
func TestRateLimitingIsRetried(t *testing.T) {
	f := newFakeServer(t)
	c := clientFor(t, f, Options{BatchLines: 10, BatchBytes: 1 << 20, Attempts: 3})
	sp := spoolIn(t, c, t.TempDir(), payload(10, ""))

	f.failBatchTimes(0, 429, 1)
	if _, err := c.Send(context.Background(), sp); err != nil {
		t.Fatalf("a 429 was not retried: %v", err)
	}
	if got := f.storedComponents(); got != 10 {
		t.Errorf("the server stored %d components, want 10", got)
	}
}

// TestCloseMismatchIsAnErrorNotAWarning. This is the §5 incident's detection
// point. A 409 has to fail loudly; a 200 with a warning field is what nobody
// reads.
func TestCloseMismatchIsAnErrorNotAWarning(t *testing.T) {
	f := newFakeServer(t)
	c := clientFor(t, f, Options{BatchLines: 100, BatchBytes: 1 << 20, Attempts: 2})

	// A payload whose manifest lies: it declares 3993 and carries 15.
	body := strings.Replace(payload(15, ""), `"component":15`, `"component":3993`, 1)
	sp := spoolIn(t, c, t.TempDir(), body)

	_, err := c.Send(context.Background(), sp)
	if err == nil {
		t.Fatal("a scan declaring 3993 components and sending 15 was accepted")
	}
	if !IsPermanent(err) {
		t.Errorf("the mismatch was treated as retryable: %v", err)
	}
	for _, want := range []string{"409", "3993", "15"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q, so nobody can act on it: %v", want, err)
		}
	}
}

// TestNewRefusesConfigurationThatCannotWork. Every one of these would
// otherwise surface only after a multi-minute scan.
func TestNewRefusesConfigurationThatCannotWork(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{"no scheme", Options{BaseURL: "riskability.example", Token: "t"}, "no scheme"},
		{"empty url", Options{Token: "t"}, "empty server URL"},
		{"no credentials", Options{BaseURL: "https://x.test/api/v1"}, "no credentials"},
		{"half a certificate", Options{BaseURL: "https://x.test/api/v1", ClientCertFile: "c.pem"}, "both the certificate and its key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.opts); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("New() error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// TestBaseURLAcceptsBothFormsAnOperatorIsGiven.
func TestBaseURLAcceptsBothFormsAnOperatorIsGiven(t *testing.T) {
	for _, in := range []string{
		"https://r.example/api/v1",
		"https://r.example/api/v1/",
		"https://r.example/api/v1/ingest",
	} {
		got, err := normalizeBase(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != "https://r.example/api/v1/ingest" {
			t.Errorf("normalizeBase(%q) = %q", in, got)
		}
	}
}
