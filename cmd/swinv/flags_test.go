package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chrzz/swinv/internal/model"
)

func TestParseFlagsDefaults(t *testing.T) {
	cfg, code, err := parseFlags(nil, new(bytes.Buffer))
	if err != nil {
		t.Fatalf("unexpected error: %v (code %d)", err, code)
	}
	if cfg.root != "/" {
		t.Errorf("root = %q, want /", cfg.root)
	}
	if cfg.out != "/var/lib/swinv" {
		t.Errorf("out = %q, want /var/lib/swinv", cfg.out)
	}
	if cfg.format != "json,csv" {
		t.Errorf("format = %q, want json,csv", cfg.format)
	}
	if cfg.outputMode != modeDated {
		t.Errorf("outputMode = %q, want %q", cfg.outputMode, modeDated)
	}
	if !cfg.latestSymlink {
		t.Error("latestSymlink should default to true")
	}
	if cfg.timeout != 30*time.Minute {
		t.Errorf("timeout = %s, want 30m", cfg.timeout)
	}
}

func TestParseFlagsErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"unknown output mode", []string{"--output-mode", "rotate"}, "unknown --output-mode"},
		{"empty root", []string{"--root", ""}, "--root must not be empty"},
		{"negative timeout", []string{"--timeout", "-1s"}, "--timeout must be positive"},
		{"negative parallelism", []string{"--parallelism", "-2"}, "--parallelism must not be negative"},
		{"quiet and verbose", []string{"--quiet", "--verbose"}, "mutually exclusive"},
		{"name with stdout", []string{"--stdout", "--name", "x"}, "--name has no meaning"},
		{"positional arg", []string{"extra"}, "unexpected argument"},
		{"delta-only without since", []string{"--delta-only"}, "--delta-only requires --since"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, code, err := parseFlags(tt.args, new(bytes.Buffer))
			if err == nil {
				t.Fatalf("expected an error containing %q", tt.want)
			}
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d", code, exitUsage)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

// TestOutputModeSelectsNameTemplate covers the owner's requirement that the
// tool can either overwrite one file or create a new file per run.
func TestOutputModeSelectsNameTemplate(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{nil, "{hostname}-{date}"},
		{[]string{"--output-mode", "dated"}, "{hostname}-{date}"},
		{[]string{"--output-mode", "overwrite"}, "{hostname}"},
		{[]string{"--output-mode", "timestamped"}, "{hostname}-{datetime}"},
		{[]string{"--output-mode", "OVERWRITE"}, "{hostname}"},
		// An explicit --name always wins over the mode.
		{[]string{"--output-mode", "overwrite", "--name", "custom-{machine_id}"}, "custom-{machine_id}"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			cfg, _, err := parseFlags(tt.args, new(bytes.Buffer))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := cfg.effectiveName(); got != tt.want {
				t.Errorf("effectiveName() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDeltaFlags covers the --since / --delta-only pairing.
func TestDeltaFlags(t *testing.T) {
	cfg, _, err := parseFlags([]string{"--since", "old.json", "--delta-only"}, new(bytes.Buffer))
	if err != nil {
		t.Fatalf("--since with --delta-only should be accepted: %v", err)
	}
	if cfg.since != "old.json" || !cfg.deltaOnly {
		t.Errorf("since=%q deltaOnly=%v, want old.json/true", cfg.since, cfg.deltaOnly)
	}

	// --since alone is fine and keeps the full inventory.
	cfg, _, err = parseFlags([]string{"--since", "old.json"}, new(bytes.Buffer))
	if err != nil || cfg.deltaOnly {
		t.Errorf("--since alone should be accepted with deltaOnly=false (err=%v)", err)
	}

	// --hash defaults off; it costs real I/O so it must be opt-in.
	cfg, _, err = parseFlags(nil, new(bytes.Buffer))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.hash {
		t.Error("--hash must default to false")
	}
}

// TestLoadBaselineRejectsNonReports: --since must not silently accept an
// arbitrary JSON file and then report the entire inventory as "added".
func TestLoadBaselineRejectsNonReports(t *testing.T) {
	dir := t.TempDir()
	notAReport := filepath.Join(dir, "other.json")
	if err := os.WriteFile(notAReport, []byte(`{"hello":"world"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBaseline(notAReport); err == nil {
		t.Error("expected an error for a JSON file that is not an swinv report")
	}

	if _, err := loadBaseline(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected an error for a missing baseline file")
	}

	// A --delta-only report holds only the changed components. Using it as a
	// baseline would report every unchanged package as newly added.
	deltaOnly := filepath.Join(dir, "deltaonly.json")
	if err := os.WriteFile(deltaOnly, []byte(
		`{"schema_version":"1.1","delta":{"since":"x","delta_only":true},"components":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBaseline(deltaOnly); err == nil {
		t.Error("a --delta-only report must be refused as a --since baseline")
	} else if !strings.Contains(err.Error(), "delta-only") {
		t.Errorf("error %q should explain that the file is a delta, not an inventory", err)
	}

	// A full report that merely *contains* a delta block is a valid baseline.
	withDelta := filepath.Join(dir, "withdelta.json")
	if err := os.WriteFile(withDelta, []byte(
		`{"schema_version":"1.1","delta":{"since":"x"},"components":[{"name":"a","version":"1","type":"deb"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBaseline(withDelta); err != nil {
		t.Errorf("a full report containing a delta block should be a valid baseline: %v", err)
	}

	malformed := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(malformed, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBaseline(malformed); err == nil {
		t.Error("expected an error for malformed JSON")
	}
}

func TestExpandName(t *testing.T) {
	report := &model.Report{
		Host: model.Host{Hostname: "web-01", MachineID: "abc123"},
		Scan: model.ScanMeta{StartedAt: time.Date(2024, 3, 9, 14, 5, 6, 0, time.UTC)},
	}
	tests := []struct{ tmpl, want string }{
		{"{hostname}-{date}", "web-01-20240309"},
		{"{hostname}", "web-01"},
		{"{hostname}-{datetime}", "web-01-20240309T140506Z"},
		{"{machine_id}", "abc123"},
		{"inventory", "inventory"},
	}
	for _, tt := range tests {
		t.Run(tt.tmpl, func(t *testing.T) {
			if got := expandName(tt.tmpl, report); got != tt.want {
				t.Errorf("expandName(%q) = %q, want %q", tt.tmpl, got, tt.want)
			}
		})
	}
}

// TestExpandNameSanitizes makes sure a hostile hostname cannot escape --out.
func TestExpandNameSanitizes(t *testing.T) {
	report := &model.Report{
		Host: model.Host{Hostname: "../../etc/pas swd"},
		Scan: model.ScanMeta{StartedAt: time.Date(2024, 3, 9, 0, 0, 0, 0, time.UTC)},
	}
	got := expandName("{hostname}-{date}", report)
	if strings.ContainsAny(got, "/\\ ") {
		t.Errorf("expandName produced an unsafe filename: %q", got)
	}
}

func TestExpandNameEmptyHostname(t *testing.T) {
	report := &model.Report{Scan: model.ScanMeta{StartedAt: time.Now()}}
	if got := expandName("{hostname}", report); got != "unknown-host" {
		t.Errorf("expandName with empty hostname = %q, want unknown-host", got)
	}
}

func TestParseFormats(t *testing.T) {
	tests := []struct {
		list      string
		forStdout bool
		want      []string
		wantErr   string
	}{
		{"json,csv", false, []string{"json", "csv"}, ""},
		{" json , csv ", false, []string{"json", "csv"}, ""},
		{"json,json", false, []string{"json"}, ""},
		{"json", true, []string{"json"}, ""},
		{"json,csv", true, nil, "requires exactly one"},
		{"", false, nil, "is empty"},
		{"xml", false, nil, "unknown --format"},
	}
	for _, tt := range tests {
		t.Run(tt.list, func(t *testing.T) {
			got, err := parseFormats(tt.list, tt.forStdout)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
