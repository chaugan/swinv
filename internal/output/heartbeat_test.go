package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

func heartbeatReport() *model.Report {
	r := serviceReport()
	r.Host.MachineID = "0123456789abcdef"
	r.Scan.InventoryDigest = "sha256:9f2cabc"
	return r
}

// The heartbeat carries enough to keep a consumer's host record fed on a scan
// that sends no components at all.
func TestNDJSONHeartbeat(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, heartbeatReport()); err != nil {
		t.Fatalf("WriteNDJSON: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want heartbeat + 2 components", len(lines))
	}

	var hb struct {
		RecordType   string `json:"record_type"`
		Hostname     string `json:"hostname"`
		Digest       string `json:"digest"`
		NComponents  int    `json:"n_components"`
		ScannedAt    string `json:"scanned_at"`
		MachineID    string `json:"machine_id"`
		OSID         string `json:"os_id"`
		Architecture string `json:"architecture"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &hb); err != nil {
		t.Fatalf("heartbeat is not valid JSON: %v", err)
	}
	if hb.RecordType != "heartbeat" {
		t.Errorf("record_type = %q", hb.RecordType)
	}
	if hb.Digest != "sha256:9f2cabc" || hb.NComponents != 2 {
		t.Errorf("heartbeat = %+v", hb)
	}
	if hb.Hostname != "web01" || hb.MachineID == "" || hb.OSID == "" || hb.Architecture == "" {
		t.Errorf("heartbeat lacks the host identity a consumer needs: %+v", hb)
	}
	if hb.ScannedAt == "" {
		t.Error("heartbeat has no scanned_at")
	}

	// A component record carries no record_type, which is what every line was
	// before the heartbeat existed and what existing consumers assume.
	var component map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &component); err != nil {
		t.Fatalf("component line is not valid JSON: %v", err)
	}
	if _, ok := component["record_type"]; ok {
		t.Error("a component line grew a record_type, changing every existing line")
	}
}

// The whole point: an unchanged host sends one line instead of fourteen
// thousand.
func TestNDJSONHeartbeatSuppressesComponents(t *testing.T) {
	r := heartbeatReport()
	r.Scan.InventoryUnchanged = true

	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, r); err != nil {
		t.Fatalf("WriteNDJSON: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want only the heartbeat", len(lines))
	}
	// n_components still states how many there are, so a quiet host stays
	// distinguishable from an empty one.
	var hb struct {
		NComponents int `json:"n_components"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &hb); err != nil {
		t.Fatal(err)
	}
	if hb.NComponents != 2 {
		t.Errorf("n_components = %d, want the real count even though none were sent", hb.NComponents)
	}
}

// Without --heartbeat nothing changes at all, which is what every existing
// consumer is reading today.
func TestNDJSONWithoutHeartbeatIsUnchanged(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, serviceReport()); err != nil {
		t.Fatalf("WriteNDJSON: %v", err)
	}
	if strings.Contains(buf.String(), "heartbeat") {
		t.Error("a report with no digest emitted a heartbeat")
	}
	if n := strings.Count(strings.TrimRight(buf.String(), "\n"), "\n") + 1; n != 2 {
		t.Errorf("got %d lines, want 2 components", n)
	}
}

// InventoryUnchanged must never silence a format whose empty form would be a
// false statement: a CSV with no rows says nothing is installed.
func TestOtherFormatsIgnoreInventoryUnchanged(t *testing.T) {
	r := heartbeatReport()
	r.Scan.InventoryUnchanged = true

	for _, format := range []string{"json", "csv", "cyclonedx-json"} {
		write, _, err := WriterFor(format)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := write(&buf, r); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if !strings.Contains(buf.String(), "openssh-server") {
			t.Errorf("%s dropped its components because the inventory was unchanged", format)
		}
	}
}
