package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

func configReport() *model.Report {
	r := serviceReport()
	r.NDJSONInclude = []string{model.RecordConfig}
	r.ConfigSurface = []model.ConfigEntry{
		{Kind: model.ConfigKindCron, Path: "/etc/crontab", User: "root",
			Schedule: "0 3 * * *", Command: "/usr/local/bin/rotate.sh",
			Executable: "/usr/local/bin/rotate.sh", Attack: "T1053.003",
			WorldWritable: true,
			Evidence:      []string{"/usr/local/bin/rotate.sh is world-writable (mode 0777)"}},
		{Kind: model.ConfigKindSUID, Name: "sudo", Path: "/usr/bin/sudo",
			Executable: "/usr/bin/sudo", Mode: "4755", SetUID: true,
			PURL: "pkg:deb/ubuntu/sudo@1.9.15", Attack: "T1548.001"},
	}
	return r
}

func TestNDJSONConfigRecords(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, configReport()); err != nil {
		t.Fatal(err)
	}
	rows := recordsOfType(t, buf.Bytes(), "config")
	if len(rows) != 2 {
		t.Fatalf("got %d config records, want 2", len(rows))
	}

	byKind := map[string]map[string]any{}
	for _, r := range rows {
		byKind[r["kind"].(string)] = r
	}
	cron := byKind["cron"]
	if cron["attack"] != "T1053.003" || cron["world_writable"] != true {
		t.Errorf("cron record = %v", cron)
	}
	if cron["root"] != "/" {
		t.Errorf("root = %v, want /", cron["root"])
	}
	if cron["evidence_text"] == nil || cron["n_evidence"] != float64(1) {
		t.Errorf("evidence twins missing: %v", cron)
	}
	suid := byKind["suid"]
	if suid["purl"] != "pkg:deb/ubuntu/sudo@1.9.15" || suid["mode"] != "4755" || suid["setuid"] != true {
		t.Errorf("suid record = %v", suid)
	}

	// The no-null contract holds for the new record type too.
	if strings.Contains(buf.String(), "null") {
		t.Error("a config record carries a JSON null; Splunk indexes that as the string \"null\"")
	}
}

// Config records are emitted even on an unchanged heartbeat scan: the digest
// tracks installed software, not configuration, so a new cron job on an
// unchanged host is exactly what suppression would hide.
func TestConfigRecordsSurviveAnUnchangedHeartbeat(t *testing.T) {
	r := configReport()
	r.Scan.InventoryDigest = "sha256:abc"
	r.Scan.InventoryUnchanged = true

	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if got := len(recordsOfType(t, buf.Bytes(), "config")); got != 2 {
		t.Errorf("%d config records on an unchanged scan, want 2", got)
	}
	manifest, _ := decodeStream(t, buf.Bytes())
	if manifest["counts"].(map[string]any)["config"] != float64(2) {
		t.Errorf("counts.config = %v, want 2", manifest["counts"].(map[string]any)["config"])
	}
}

func TestConfigRecordsAreOptIn(t *testing.T) {
	r := configReport()
	r.NDJSONInclude = nil
	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if got := len(recordsOfType(t, buf.Bytes(), "config")); got != 0 {
		t.Errorf("%d config records without --ndjson-include", got)
	}
}
