package transmit

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeServer is docs/API.md's ingest surface, implemented only as far as the
// client can tell.
//
// It is deliberately strict about the two things the contract exists for: a
// batch is idempotent on (scan_id, index), and a close whose declared and
// stored counts disagree answers 409 with both numbers rather than 200 with a
// warning field nobody reads.
type fakeServer struct {
	*httptest.Server

	mu sync.Mutex

	Manifest map[string]any
	Declared int

	// Batches maps batch index to the records it carried. A map, not a slice,
	// so a re-sent batch overwrites rather than appends and the duplicate is
	// visible as an unchanged total.
	Batches map[int][]string

	// Deliveries counts every accepted batch POST, duplicates included, so a
	// test can tell "sent twice, stored once" from "sent once".
	Deliveries map[int]int

	Gzipped map[int]bool
	Auth    []string

	// failBatch, when set, makes that batch index fail with failStatus until
	// failRemaining reaches zero.
	failBatch     int
	failStatus    int
	failRemaining int

	Closed bool
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{
		Batches:    map[int][]string{},
		Deliveries: map[int]int{},
		Gzipped:    map[int]bool{},
		failBatch:  -1,
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.Close)
	return f
}

// failBatchTimes makes batch index fail status the next n times it is posted.
func (f *fakeServer) failBatchTimes(index, status, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failBatch, f.failStatus, f.failRemaining = index, status, n
}

// storedComponents counts component records across every stored batch.
func (f *fakeServer) storedComponents() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, lines := range f.Batches {
		for _, l := range lines {
			var probe struct {
				RecordType string `json:"record_type"`
			}
			if err := json.Unmarshal([]byte(l), &probe); err != nil {
				continue
			}
			if probe.RecordType == "" {
				n++
			}
		}
	}
	return n
}

// resumeFrom is the first batch index the server has not stored.
func (f *fakeServer) resumeFrom() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := 0
	for {
		if _, ok := f.Batches[i]; !ok {
			return i
		}
		i++
	}
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	f.Auth = append(f.Auth, r.Header.Get("Authorization"))
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/ingest")

	switch {
	case path == "/scan" && r.Method == http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		_ = json.Unmarshal(body, &f.Manifest)
		if counts, ok := f.Manifest["counts"].(map[string]any); ok {
			if c, ok := counts["component"].(float64); ok {
				f.Declared = int(c)
			}
		}
		f.mu.Unlock()
		writeJSON(w, map[string]any{"scan_id": f.scanID(), "resume_from": f.resumeFrom()})

	case strings.HasPrefix(path, "/scan/") && strings.Contains(path, "/batch/"):
		f.handleBatch(w, r, path)

	case strings.HasSuffix(path, "/status") && r.Method == http.MethodGet:
		writeJSON(w, map[string]any{
			"scan_id":          f.scanID(),
			"resume_from":      f.resumeFrom(),
			"records_received": f.storedComponents(),
		})

	case strings.HasSuffix(path, "/close") && r.Method == http.MethodPost:
		f.mu.Lock()
		f.Closed = true
		declared := f.Declared
		f.mu.Unlock()
		stored := f.storedComponents()
		if declared != stored {
			w.WriteHeader(http.StatusConflict)
			writeJSON(w, map[string]any{
				"scan_id": f.scanID(), "declared_components": declared,
				"stored_components": stored, "reconciled": false,
				"message": fmt.Sprintf("declared %d, stored %d", declared, stored),
			})
			return
		}
		writeJSON(w, map[string]any{
			"scan_id": f.scanID(), "declared_components": declared,
			"stored_components": stored, "reconciled": true,
		})

	default:
		http.Error(w, "no such route: "+path, http.StatusNotFound)
	}
}

func (f *fakeServer) handleBatch(w http.ResponseWriter, r *http.Request, path string) {
	idx, err := strconv.Atoi(path[strings.LastIndex(path, "/")+1:])
	if err != nil {
		http.Error(w, "bad batch index", http.StatusBadRequest)
		return
	}
	if r.Header.Get("Idempotency-Key") == "" {
		http.Error(w, "no idempotency key", http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	if idx == f.failBatch && f.failRemaining > 0 {
		f.failRemaining--
		status := f.failStatus
		f.mu.Unlock()
		http.Error(w, "injected failure", status)
		return
	}
	f.mu.Unlock()

	var reader io.Reader = r.Body
	gz := r.Header.Get("Content-Encoding") == "gzip"
	if gz {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		defer func() { _ = zr.Close() }()
		reader = zr
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var lines []string
	for _, l := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}

	f.mu.Lock()
	f.Batches[idx] = lines
	f.Deliveries[idx]++
	f.Gzipped[idx] = gz
	f.mu.Unlock()

	w.WriteHeader(http.StatusAccepted)
}

func (f *fakeServer) scanID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.Manifest["scan_id"].(string); ok && id != "" {
		return id
	}
	return "server-minted"
}

func (f *fakeServer) baseURL() string { return f.URL + "/api/v1" }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(v)
	_, _ = w.Write(buf.Bytes())
}
