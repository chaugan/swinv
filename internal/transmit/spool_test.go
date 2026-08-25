package transmit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// payload builds an NDJSON scan: a manifest line declaring n components,
// followed by n component records.
func payload(n int, pad string) string {
	var b strings.Builder
	manifest, _ := json.Marshal(map[string]any{
		"record_type":    "heartbeat",
		"hostname":       "web01",
		"scan_id":        "test-scan",
		"schema_version": 2,
		"counts":         map[string]int{"component": n, "exposure": 0, "container": 0},
	})
	b.Write(manifest)
	b.WriteString("\n")
	for i := 0; i < n; i++ {
		line, _ := json.Marshal(map[string]any{
			"hostname": "web01",
			"name":     fmt.Sprintf("pkg-%04d", i),
			"version":  "1.0",
			"type":     "deb",
			"pad":      pad,
		})
		b.Write(line)
		b.WriteString("\n")
	}
	return b.String()
}

func spoolFor(t *testing.T, body string, lines, bytesLimit int) *Spool {
	t.Helper()
	c, err := New(Options{BaseURL: "https://example.test/api/v1", Token: "t",
		BatchLines: lines, BatchBytes: bytesLimit})
	if err != nil {
		t.Fatal(err)
	}
	sp, err := c.NewSpool(t.TempDir(), "test-scan", "web01", 0, 0o600, 0o700,
		func(w io.Writer) error {
			_, err := io.WriteString(w, body)
			return err
		})
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

// TestBatchingSplitsOnLineCount is the ordinary boundary: 10 records at 4 per
// batch is 4 + 4 + 2, and the manifest is not one of them.
func TestBatchingSplitsOnLineCount(t *testing.T) {
	sp := spoolFor(t, payload(10, ""), 4, 1<<20)

	var sizes []int
	var total int
	if err := sp.EachBatch(func(index int, body []byte, lines int) error {
		if index != len(sizes) {
			t.Errorf("batch index %d arrived at position %d; indexes must be dense and ordered "+
				"or a resume point means nothing", index, len(sizes))
		}
		if got := strings.Count(string(body), "\n"); got != lines {
			t.Errorf("batch %d reports %d lines and carries %d", index, lines, got)
		}
		if strings.Contains(string(body), `"record_type":"heartbeat"`) {
			t.Errorf("batch %d carries the manifest; it was already delivered by the open call "+
				"and would be stored as a component", index)
		}
		sizes = append(sizes, lines)
		total += lines
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	want := []int{4, 4, 2}
	if fmt.Sprint(sizes) != fmt.Sprint(want) {
		t.Errorf("batch sizes = %v, want %v", sizes, want)
	}
	if total != 10 {
		t.Errorf("sent %d records, want 10: every record line must appear in exactly one batch", total)
	}
}

// TestBatchingSplitsOnBytesFirst pins the half of the rule that the line count
// cannot express: a host with large records puts far fewer than the line limit
// into a sane request body.
func TestBatchingSplitsOnBytesFirst(t *testing.T) {
	body := payload(10, strings.Repeat("x", 200))
	sp := spoolFor(t, body, 1000, 600)

	batches := 0
	total := 0
	if err := sp.EachBatch(func(_ int, b []byte, lines int) error {
		if len(b) > 600 && lines > 1 {
			t.Errorf("batch of %d bytes over the 600-byte limit with %d lines", len(b), lines)
		}
		batches++
		total += lines
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if batches < 5 {
		t.Errorf("got %d batches; the byte limit should have split well before the 1000-line limit", batches)
	}
	if total != 10 {
		t.Errorf("sent %d records, want 10", total)
	}
}

// TestBatchingNeverStallsOnAnOversizeLine: one record larger than the byte
// limit goes on its own rather than blocking the upload for ever.
func TestBatchingNeverStallsOnAnOversizeLine(t *testing.T) {
	sp := spoolFor(t, payload(3, strings.Repeat("y", 4000)), 1000, 512)

	batches, total := 0, 0
	if err := sp.EachBatch(func(_ int, _ []byte, lines int) error {
		if lines == 0 {
			t.Fatal("empty batch: an oversize line produced a batch with nothing in it")
		}
		batches++
		total += lines
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if batches != 3 || total != 3 {
		t.Errorf("got %d batches carrying %d records, want 3 and 3", batches, total)
	}
}

// TestRecordsCountsWhatWillBeSent is the collector-side half of the
// reconciliation: the number the manifest declares has to be the number of
// record lines the payload actually holds.
func TestRecordsCountsWhatWillBeSent(t *testing.T) {
	sp := spoolFor(t, payload(37, ""), 5, 1<<20)
	n, err := sp.Records()
	if err != nil {
		t.Fatal(err)
	}
	if n != 37 {
		t.Errorf("Records() = %d, want 37", n)
	}

	manifest, err := sp.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		RecordType string         `json:"record_type"`
		Counts     map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}
	if m.RecordType != "heartbeat" {
		t.Errorf("manifest record_type = %q", m.RecordType)
	}
	if m.Counts["component"] != n {
		t.Errorf("the manifest declares %d components and the payload holds %d; "+
			"the server would report a discrepancy that is really the collector's",
			m.Counts["component"], n)
	}
}

// TestManifestRefusesAScanWithoutOne. A stream with no manifest is exactly the
// pipeline that cannot tell "nothing to find" from "nothing arrived", so it is
// refused rather than uploaded.
func TestManifestRefusesAScanWithoutOne(t *testing.T) {
	sp := spoolFor(t, `{"hostname":"web01","name":"bash","type":"deb"}`+"\n", 10, 1<<20)
	if _, err := sp.Manifest(); err == nil {
		t.Fatal("a payload whose first line is a component was accepted")
	} else if !strings.Contains(err.Error(), "manifest") {
		t.Errorf("error does not say what is missing: %v", err)
	}
}

// TestBatchBoundariesSurviveAFlagChange. The state file, not the current
// flags, defines where batch n starts -- otherwise a resume with different
// --transmit-batch-lines would send records the server already stored under a
// different index, and idempotency on (scan_id, index) would not catch it.
func TestBatchBoundariesSurviveAFlagChange(t *testing.T) {
	dir := t.TempDir()
	c, _ := New(Options{BaseURL: "https://example.test/api/v1", Token: "t", BatchLines: 4, BatchBytes: 1 << 20})
	body := payload(10, "")
	if _, err := c.NewSpool(dir, "test-scan", "web01", 10, 0o600, 0o700, func(w io.Writer) error {
		_, err := io.WriteString(w, body)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// A later run, configured differently, picks the spool up.
	pending, err := Pending(dir, c.base)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("Pending found %d spools, want 1", len(pending))
	}
	var sizes []int
	if err := pending[0].EachBatch(func(_ int, _ []byte, lines int) error {
		sizes = append(sizes, lines)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(sizes) != fmt.Sprint([]int{4, 4, 2}) {
		t.Errorf("batch sizes after reload = %v, want [4 4 2]", sizes)
	}
}

// TestPendingIgnoresAnotherServersQueue. Re-pointing --transmit is deliberate;
// its backlog is not ours to deliver.
func TestPendingIgnoresAnotherServersQueue(t *testing.T) {
	dir := t.TempDir()
	c, _ := New(Options{BaseURL: "https://a.test/api/v1", Token: "t"})
	if _, err := c.NewSpool(dir, "scan-a", "web01", 1, 0o600, 0o700, func(w io.Writer) error {
		_, err := io.WriteString(w, payload(1, ""))
		return err
	}); err != nil {
		t.Fatal(err)
	}

	other, _ := New(Options{BaseURL: "https://b.test/api/v1", Token: "t"})
	pending, err := Pending(dir, other.base)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("a spool queued for another server was picked up: %d", len(pending))
	}
}

// TestSpoolNameCannotEscapeTheDirectory. The scan id can come back from the
// server, which makes it untrusted input used as a filename.
func TestSpoolNameCannotEscapeTheDirectory(t *testing.T) {
	for _, id := range []string{"../../etc/cron.d/x", "/etc/passwd", "..", ""} {
		got := sanitizeSpoolName(id)
		if strings.ContainsAny(got, `/\.`) || got == "" {
			t.Errorf("sanitizeSpoolName(%q) = %q, which can still name a path", id, got)
		}
	}
}

// TestAckIsOnlyEverRecordedForward. A state file that runs ahead of the server
// is how a resume skips a batch nobody stored.
func TestAckIsOnlyEverRecordedForward(t *testing.T) {
	sp := spoolFor(t, payload(10, ""), 4, 1<<20)
	for _, i := range []int{0, 1, 0} {
		if err := sp.Ack(i); err != nil {
			t.Fatal(err)
		}
	}
	if got := sp.State().Acked; got != 2 {
		t.Errorf("Acked = %d, want 2: a late acknowledgement must not rewind the resume point", got)
	}

	raw, err := os.ReadFile(filepath.Join(sp.dir, sp.name+spoolStateExt))
	if err != nil {
		t.Fatal(err)
	}
	var st SpoolState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.Acked != 2 {
		t.Errorf("on-disk Acked = %d, want 2: the resume point has to survive the process", st.Acked)
	}
}
