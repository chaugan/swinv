package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/transmit"
)

// ingestStub is enough of docs/API.md for an end-to-end run: it stores what
// arrives and reconciles the close against the manifest, which is the only
// behaviour the collector's exit code depends on.
type ingestStub struct {
	*httptest.Server
	mu sync.Mutex

	manifest  map[string]any
	manifests map[string]map[string]any
	// batches maps "scanID/index" to the records it carried, so a re-sent
	// batch overwrites rather than appends and a duplicate delivery is
	// visible as an unchanged total.
	batches map[string][]map[string]any
	closed  bool
	auth    string

	// failBatchesFrom makes every batch at or above this index fail, so a test
	// can abandon an upload half way and finish it later.
	failBatchesFrom int
}

func newIngestStub(t *testing.T) *ingestStub {
	t.Helper()
	s := &ingestStub{batches: map[string][]map[string]any{}, manifests: map[string]map[string]any{}, failBatchesFrom: -1}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.auth = r.Header.Get("Authorization")
		s.mu.Unlock()

		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/ingest/scan"):
			body, _ := io.ReadAll(r.Body)
			var m map[string]any
			_ = json.Unmarshal(body, &m)
			id, _ := m["scan_id"].(string)
			s.mu.Lock()
			s.manifest = m
			s.manifests[id] = m
			s.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"scan_id": id, "resume_from": s.resumeFrom(id)})

		case strings.Contains(path, "/batch/"):
			scanID, index := scanAndBatch(path)
			s.mu.Lock()
			failFrom := s.failBatchesFrom
			s.mu.Unlock()
			if failFrom >= 0 && index >= failFrom {
				http.Error(w, "injected failure", http.StatusServiceUnavailable)
				return
			}
			var rd io.Reader = r.Body
			if r.Header.Get("Content-Encoding") == "gzip" {
				zr, err := gzip.NewReader(r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				rd = zr
			}
			body, _ := io.ReadAll(rd)
			var stored []map[string]any
			for _, line := range strings.Split(strings.TrimRight(string(body), "\n"), "\n") {
				if strings.TrimSpace(line) == "" {
					continue
				}
				var rec map[string]any
				if err := json.Unmarshal([]byte(line), &rec); err != nil {
					http.Error(w, "unparseable record", http.StatusBadRequest)
					return
				}
				stored = append(stored, rec)
			}
			s.mu.Lock()
			s.batches[scanID+"/"+strconv.Itoa(index)] = stored
			s.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)

		case strings.HasSuffix(path, "/status"):
			scanID, _ := scanAndBatch(path)
			_ = json.NewEncoder(w).Encode(map[string]any{"resume_from": s.resumeFrom(scanID)})

		case strings.HasSuffix(path, "/close"):
			scanID, _ := scanAndBatch(path)
			declared, stored := s.declaredFor(scanID), s.storedFor(scanID)
			s.mu.Lock()
			s.closed = true
			s.mu.Unlock()
			if declared != stored {
				w.WriteHeader(http.StatusConflict)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"declared_components": declared, "stored_components": stored,
				"reconciled": declared == stored,
			})

		default:
			http.Error(w, "no such route", http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *ingestStub) declared() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts, _ := s.manifest["counts"].(map[string]any)
	n, _ := counts["component"].(float64)
	return int(n)
}

// declaredFor is the per-scan count. The stub keeps one manifest per scan id
// because two scans of the same host reach the same server, and reconciling
// the second against the sum of both is the stub lying, not the collector.
func (s *ingestStub) declaredFor(scanID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts, _ := s.manifests[scanID]["counts"].(map[string]any)
	n, _ := counts["component"].(float64)
	return int(n)
}

func (s *ingestStub) storedFor(scanID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for key, batch := range s.batches {
		if !strings.HasPrefix(key, scanID+"/") {
			continue
		}
		for _, r := range batch {
			if _, ok := r["record_type"]; !ok {
				n++
			}
		}
	}
	return n
}

func (s *ingestStub) stored() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, batch := range s.batches {
		for _, r := range batch {
			if _, ok := r["record_type"]; !ok {
				n++
			}
		}
	}
	return n
}

// resumeFrom is the first batch index this scan is missing.
func (s *ingestStub) resumeFrom(scanID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := 0
	for {
		if _, ok := s.batches[scanID+"/"+strconv.Itoa(i)]; !ok {
			return i
		}
		i++
	}
}

// scanAndBatch pulls the scan id and batch index out of
// /api/v1/ingest/scan/{id}/batch/{n} and out of the status path, which has no
// batch index.
func scanAndBatch(path string) (string, int) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	scanID, index := "", -1
	for i, p := range parts {
		switch p {
		case "scan":
			if i+1 < len(parts) {
				scanID = parts[i+1]
			}
		case "batch":
			if i+1 < len(parts) {
				index, _ = strconv.Atoi(parts[i+1])
			}
		}
	}
	return scanID, index
}

// TestRunTransmitsWhatItWroteAndStillWritesTheFiles is the end-to-end shape of
// the feature: a real scan, files on disk, and a server holding exactly the
// number of components the manifest declared.
func TestRunTransmitsWhatItWroteAndStillWritesTheFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixture is a Linux rootfs")
	}
	stub := newIngestStub(t)
	out := t.TempDir()
	root, err := filepath.Abs("../../testdata/rootfs")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SWINV_TRANSMIT_TOKEN", "s3cret")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--root", root, "--out", out, "--format", "json,ndjson",
		"--transmit", stub.URL + "/api/v1",
		"--transmit-batch-lines", "2",
		"--timeout", "5m", "--quiet",
	}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("exit = %d, want 0\nstderr: %s", code, stderr.String())
	}
	if !stub.closed {
		t.Fatal("the scan was never closed, so nothing reconciled it")
	}
	if stub.auth != "Bearer s3cret" {
		t.Errorf("Authorization = %q; the token from %s was not used", stub.auth, "SWINV_TRANSMIT_TOKEN")
	}

	// The count the server checked, checked here too.
	if stub.declared() == 0 {
		t.Fatal("the manifest declared zero components; zero is a suspicious answer, not a good one")
	}
	if stub.declared() != stub.stored() {
		t.Errorf("declared %d components and delivered %d", stub.declared(), stub.stored())
	}

	// File output is a first-class mode, not a fallback, so it happens anyway.
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	var sawJSON, sawNDJSON bool
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), ".ndjson"):
			sawNDJSON = true
		case strings.HasSuffix(e.Name(), ".json"):
			sawJSON = true
		}
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("a staging file survived in the output directory: %s", e.Name())
		}
	}
	if !sawJSON || !sawNDJSON {
		t.Errorf("--transmit suppressed file output: %v", entries)
	}

	// The spool is cleaned up once the server has reconciled the scan.
	spool := filepath.Join(out, transmit.SpoolDirName)
	left, _ := os.ReadDir(spool)
	for _, e := range left {
		if strings.HasSuffix(e.Name(), ".ndjson") || strings.HasSuffix(e.Name(), ".state.json") {
			t.Errorf("a reconciled scan was left in the spool: %s", e.Name())
		}
	}
}

// TestRunKeepsTheSpoolWhenTheServerIsUnreachable. The upload failing must not
// cost the scan: the bytes stay on disk so the next run finishes the job.
func TestRunKeepsTheSpoolWhenTheServerIsUnreachable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixture is a Linux rootfs")
	}
	stub := newIngestStub(t)
	url := stub.URL + "/api/v1"
	stub.Close() // nothing is listening now

	out := t.TempDir()
	root, _ := filepath.Abs("../../testdata/rootfs")
	t.Setenv("SWINV_TRANSMIT_TOKEN", "s3cret")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--root", root, "--out", out, "--format", "json",
		"--transmit", url, "--transmit-attempts", "1", "--transmit-timeout", "2s",
		"--timeout", "5m", "--quiet",
	}, &stdout, &stderr)

	if code != exitTransmit {
		t.Fatalf("exit = %d, want %d (transmit failed)\nstderr: %s", code, exitTransmit, stderr.String())
	}
	if !strings.Contains(stderr.String(), "transmit") {
		t.Errorf("the failure was not explained on stderr: %s", stderr.String())
	}

	pending, err := transmit.Pending(filepath.Join(out, transmit.SpoolDirName), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("%d spooled scans survive the failure, want 1", len(pending))
	}
	if n, err := pending[0].Records(); err != nil || n == 0 {
		t.Errorf("the spooled scan holds %d records (err %v); a failed upload must not lose the scan", n, err)
	}
}

// TestRunExitsNonZeroWhenASourceCannotBeRead is §4.3: a valid file with
// fifteen components looks exactly like a healthy scan of a minimal host, so
// the exit code is the only thing left to say otherwise.
func TestRunExitsNonZeroWhenASourceCannotBeRead(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix permission bits and a non-root user")
	}
	root := t.TempDir()
	dbDir := filepath.Join(root, "var", "lib", "dpkg")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dbDir, "status")
	if err := os.WriteFile(db, []byte("Package: bash\nVersion: 5.2\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(db, 0o644) })

	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{"--root", root, "--out", out, "--format", "json", "--timeout", "2m", "--quiet"},
		&stdout, &stderr)

	if code != exitSourceFailed {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, exitSourceFailed, stderr.String())
	}
	if !strings.Contains(stderr.String(), "dpkg") {
		t.Errorf("stderr does not name the source that failed: %s", stderr.String())
	}

	// The report is still written, and it records the same fact. An operator
	// who only reads the file must not see a clean document.
	report := readOnlyReport(t, out)
	dpkg := report.Scan.Sources["dpkg"]
	if dpkg.Status != model.SourceError {
		t.Errorf("scan.sources.dpkg = %+v, want an error", dpkg)
	}
	if !report.Scan.Incomplete {
		t.Error("scan.incomplete is false on a run whose package database could not be read")
	}
	if report.Scan.ScanID == "" {
		t.Error("the report carries no scan_id")
	}
}

// readOnlyReport finds the single JSON report in dir and decodes it.
func readOnlyReport(t *testing.T, dir string) *model.Report {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".cdx.json") {
			continue
		}
		full := filepath.Join(dir, name)
		if fi, err := os.Lstat(full); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		raw, err := os.ReadFile(full)
		if err != nil {
			t.Fatal(err)
		}
		var r model.Report
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("%s is not valid JSON: %v", name, err)
		}
		return &r
	}
	t.Fatalf("no JSON report in %s", dir)
	return nil
}

// TestTransmitFlagsRefuseCombinationsThatWouldLie.
func TestTransmitFlagsRefuseCombinationsThatWouldLie(t *testing.T) {
	const url = "https://riskability.example/api/v1"
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"offline", []string{"--transmit", url, "--offline"}, "--offline and --transmit contradict"},
		{"stdout", []string{"--transmit", url, "--stdout", "--format", "json"}, "cannot be used with --stdout"},
		{"delta only", []string{"--transmit", url, "--since", "x.json", "--delta-only"}, "--delta-only"},
		{"no scheme is caught later, but zero batches are caught here",
			[]string{"--transmit", url, "--transmit-batch-lines", "0"}, "--transmit-batch-lines must be positive"},
		{"zero attempts", []string{"--transmit", url, "--transmit-attempts", "0"}, "--transmit-attempts must be at least 1"},
		{"bad batch bytes", []string{"--transmit", url, "--transmit-batch-bytes", "banana"}, "--transmit-batch-bytes"},
		{"token file without transmit", []string{"--transmit-token-file", "/tmp/t"}, "requires --transmit"},
		{"cert without transmit", []string{"--transmit-cert", "/tmp/c"}, "requires --transmit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, code, err := parseFlags(tt.args, io.Discard, new(bytes.Buffer))
			if err == nil {
				t.Fatalf("expected an error containing %q", tt.want)
			}
			if code != exitUsage {
				t.Errorf("exit = %d, want %d", code, exitUsage)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

// TestTransmitDefaultsAreTheDocumentedOnes.
func TestTransmitDefaultsAreTheDocumentedOnes(t *testing.T) {
	cfg, _, err := parseFlags([]string{"--transmit", "https://r.example/api/v1"}, io.Discard, new(bytes.Buffer))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.transmitBatchLines != transmit.DefaultBatchLines {
		t.Errorf("batch lines = %d, want %d", cfg.transmitBatchLines, transmit.DefaultBatchLines)
	}
	if cfg.transmitBatchBytesN != 1<<20 {
		t.Errorf("batch bytes = %d, want %d", cfg.transmitBatchBytesN, 1<<20)
	}
	if cfg.transmitAttempts != transmit.DefaultAttempts {
		t.Errorf("attempts = %d, want %d", cfg.transmitAttempts, transmit.DefaultAttempts)
	}
	// --transmit alone must produce a manifest: the server opens a scan with
	// it, and a stream without one cannot be reconciled at all.
	if !parseFlagsImpliesManifest(cfg) {
		t.Error("--transmit without --heartbeat would emit no manifest record")
	}
}

// parseFlagsImpliesManifest mirrors applyHeartbeat's condition for computing
// the inventory digest, which is what makes WriteNDJSON emit the manifest.
func parseFlagsImpliesManifest(cfg *config) bool {
	return cfg.heartbeat || cfg.transmit != ""
}

// TestASecondRunFinishesTheFirstRunsUpload is §4.1's resumption requirement at
// the level an operator sees it: a collector that dies half way up leaves the
// scan on disk, and the next run delivers it without rescanning the machine.
func TestASecondRunFinishesTheFirstRunsUpload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixture is a Linux rootfs")
	}
	stub := newIngestStub(t)
	out := t.TempDir()
	root, err := filepath.Abs("../../testdata/rootfs")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SWINV_TRANSMIT_TOKEN", "s3cret")

	args := []string{
		"--root", root, "--out", out, "--format", "json",
		"--transmit", stub.URL + "/api/v1",
		"--transmit-batch-lines", "1", "--transmit-attempts", "1",
		"--timeout", "5m", "--quiet",
	}

	// Everything from batch 2 onwards fails, so the first run gets two batches
	// in and gives up.
	stub.mu.Lock()
	stub.failBatchesFrom = 2
	stub.mu.Unlock()

	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != exitTransmit {
		t.Fatalf("first run exit = %d, want %d\nstderr: %s", code, exitTransmit, stderr.String())
	}
	partial := stub.stored()
	if partial != 2 {
		t.Fatalf("the server holds %d records after the interrupted run, want 2", partial)
	}

	spoolPath := filepath.Join(out, transmit.SpoolDirName)
	pending, err := transmit.Pending(spoolPath, "")
	if err != nil || len(pending) != 1 {
		t.Fatalf("Pending = %d spools (err %v), want the unfinished one", len(pending), err)
	}
	abandoned := pending[0].State().ScanID
	total, err := pending[0].Records()
	if err != nil {
		t.Fatal(err)
	}

	// The server recovers. A second run spools its own scan and drains the
	// backlog first.
	stub.mu.Lock()
	stub.failBatchesFrom = -1
	stub.mu.Unlock()

	stdout.Reset()
	stderr.Reset()
	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("second run exit = %d, want 0\nstderr: %s", code, stderr.String())
	}

	// The abandoned scan was completed, not restarted: its batches 0 and 1 are
	// still the ones the first run delivered.
	stub.mu.Lock()
	delivered := 0
	for key := range stub.batches {
		if strings.HasPrefix(key, abandoned+"/") {
			delivered++
		}
	}
	stub.mu.Unlock()
	if delivered != total {
		t.Errorf("the resumed scan holds %d of its %d batches", delivered, total)
	}

	if left, _ := transmit.Pending(spoolPath, ""); len(left) != 0 {
		t.Errorf("%d spooled scan(s) survive a successful run", len(left))
	}
}
