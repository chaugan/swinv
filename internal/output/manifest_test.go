package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

// decodeStream splits an NDJSON buffer into its manifest and a tally of the
// record types that followed, counted the way a receiver counts them: a line
// with no record_type is a component.
func decodeStream(t *testing.T, b []byte) (map[string]any, map[string]int) {
	t.Helper()
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("empty stream")
	}

	var manifest map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &manifest); err != nil {
		t.Fatalf("line 1 is not JSON: %v", err)
	}
	if manifest["record_type"] != model.RecordHeartbeat {
		t.Fatalf("line 1 is a %v record, not the manifest", manifest["record_type"])
	}

	counted := map[string]int{
		model.RecordComponent: 0, model.RecordExposure: 0, model.RecordContainer: 0,
	}
	for i, line := range lines[1:] {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not JSON: %v", i+2, err)
		}
		kind, _ := rec["record_type"].(string)
		if kind == "" {
			kind = model.RecordComponent
		}
		counted[kind]++
	}
	return manifest, counted
}

func manifestReport() *model.Report {
	r := serviceReport()
	r.Tool = model.Tool{Name: "swinv", Version: "0.7.0"}
	r.Scan.StartedAt = fixedStart
	r.Scan.DurationMS = 8412
	r.Scan.ScanID = "6d4f0e5e-1f2a-4a1b-9c3d-0a1b2c3d4e5f"
	r.Scan.InventoryDigest = "sha256:9f2cabc"
	r.Scan.Sources = map[string]model.SourceStatus{
		"dpkg": {Status: model.SourceOK, Components: 1},
		"pe":   {Status: model.SourceOK, Components: 1},
		"rpm":  {Status: model.SourceSkipped, Reason: "no rpm package database on this host"},
	}
	return r
}

// TestManifestCountsEqualTheRecordsActuallyWritten is the property the whole
// feature exists for. A stream whose first line says 3,993 and whose body
// holds 15 is the §5 incident, and it must be impossible to produce here.
func TestManifestCountsEqualTheRecordsActuallyWritten(t *testing.T) {
	r := manifestReport()
	r.NDJSONInclude = []string{recordExposure, recordContainer}
	r.Containers = []model.Container{{ID: "abc123", Name: "web", Runtime: "docker"}}
	r.Exposure = []model.Exposure{
		{Address: "0.0.0.0", Port: 22, Protocol: "tcp", Components: []string{"pkg:deb/ubuntu/openssh-server@10.2p1"}},
		{Address: "127.0.0.1", Port: 9000, Protocol: "tcp"},
	}

	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, r); err != nil {
		t.Fatalf("WriteNDJSON: %v", err)
	}
	manifest, counted := decodeStream(t, buf.Bytes())

	declared, ok := manifest["counts"].(map[string]any)
	if !ok {
		t.Fatal("the manifest carries no counts block")
	}
	for kind, got := range counted {
		want, present := declared[kind].(float64)
		if !present {
			t.Errorf("counts has no %q entry, so the receiver cannot check it", kind)
			continue
		}
		if int(want) != got {
			t.Errorf("counts.%s = %d and %d %s record(s) were written", kind, int(want), got, kind)
		}
	}
}

// TestManifestCarriesEverythingTheServerReconcilesOn.
func TestManifestCarriesEverythingTheServerReconcilesOn(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, manifestReport()); err != nil {
		t.Fatal(err)
	}
	manifest, _ := decodeStream(t, buf.Bytes())

	if manifest["schema_version"] != float64(manifestSchemaVersion) {
		t.Errorf("schema_version = %v, want %d", manifest["schema_version"], manifestSchemaVersion)
	}
	for _, field := range []string{"scan_id", "swinv_version", "counts", "sources", "duration_ms", "hostname", "scanned_at"} {
		if _, ok := manifest[field]; !ok {
			t.Errorf("the manifest has no %q", field)
		}
	}

	// The legacy field keeps its meaning exactly, or a server that predates
	// the manifest starts reading a different number without being told.
	if manifest["n_components"] != float64(2) {
		t.Errorf("n_components = %v, want 2", manifest["n_components"])
	}

	sources, ok := manifest["sources"].(map[string]any)
	if !ok {
		t.Fatal("sources is not an object")
	}
	rpm, ok := sources["rpm"].(map[string]any)
	if !ok {
		t.Fatal("sources has no rpm entry")
	}
	if rpm["status"] != model.SourceSkipped {
		t.Errorf("rpm status = %v, want %q", rpm["status"], model.SourceSkipped)
	}
	if rpm["reason"] == "" || rpm["reason"] == nil {
		t.Error("a skipped source with no reason is the same dead end as no status at all")
	}
}

// TestUnchangedInventoryDeclaresZeroAndSaysWhy.
//
// With --heartbeat an unchanged host sends no component records. The manifest
// has to declare zero, or the server reports a discrepancy on every unchanged
// scan and the reconciliation becomes noise nobody looks at.
func TestUnchangedInventoryDeclaresZeroAndSaysWhy(t *testing.T) {
	r := manifestReport()
	r.Scan.InventoryUnchanged = true

	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	manifest, counted := decodeStream(t, buf.Bytes())

	if counted[model.RecordComponent] != 0 {
		t.Fatalf("%d component records were written for an unchanged inventory", counted[model.RecordComponent])
	}
	declared := manifest["counts"].(map[string]any)
	if declared["component"] != float64(0) {
		t.Errorf("counts.component = %v, want 0: it describes this stream", declared["component"])
	}
	if manifest["inventory_unchanged"] != true {
		t.Error("nothing in the manifest explains why the count is zero")
	}
	if manifest["inventory_components"] != float64(2) {
		t.Errorf("inventory_components = %v, want 2: the host's real total is still stated",
			manifest["inventory_components"])
	}
}

// TestNoManifestWithoutADigest keeps the pre-existing contract: a run that
// asked for neither --heartbeat nor --transmit emits component lines only, and
// a consumer written before any of this reads it unchanged.
func TestNoManifestWithoutADigest(t *testing.T) {
	r := manifestReport()
	r.Scan.InventoryDigest = ""

	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	first := strings.SplitN(buf.String(), "\n", 2)[0]
	if strings.Contains(first, "record_type") {
		t.Errorf("a run with no digest grew a manifest line: %s", first)
	}
}

// TestReconcileRefusesAStreamThatWouldLie is the guard itself, exercised
// directly: the writing loop and the count that precedes it are separate
// functions, and this is what stops them drifting apart silently.
func TestReconcileRefusesAStreamThatWouldLie(t *testing.T) {
	err := reconcileNDJSON(
		map[string]int{model.RecordComponent: 3993},
		map[string]int{model.RecordComponent: 15},
	)
	if err == nil {
		t.Fatal("a manifest declaring 3993 and a body of 15 was accepted")
	}
	for _, want := range []string{"3993", "15"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %q: %v", want, err)
		}
	}
}
