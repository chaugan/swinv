package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/output"
	"github.com/chaugan/swinv/internal/scan"
)

// updateGolden regenerates the checked-in golden files. Driven by `make golden`.
var updateGolden = os.Getenv("SWINV_UPDATE_GOLDEN") == "1"

// fixedTime is a constant timestamp so golden output is stable.
var fixedTime = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

// scanFixture runs a real scan against testdata/rootfs and returns a report
// with every non-deterministic field pinned to a constant.
func scanFixture(t *testing.T) *model.Report {
	t.Helper()

	root, err := filepath.Abs("../../testdata/rootfs")
	if err != nil {
		t.Fatalf("resolving fixture root: %v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("fixture rootfs missing at %s: %v", root, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := scan.Run(ctx, scan.Options{
		Root:          root,
		FileOwnership: true,
	})
	if err != nil {
		t.Fatalf("scan.Run: %v", err)
	}

	host := model.Host{
		Hostname:     "fixture-host",
		MachineID:    "0123456789abcdef0123456789abcdef",
		Architecture: "amd64",
	}
	if result.Distro != nil {
		host.OSID = result.Distro.ID
		host.OSVersionID = result.Distro.VersionID
		host.OSPrettyName = result.Distro.PrettyName
	}
	host.Normalize()

	return &model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool: model.Tool{
			Name:        "swinv",
			Version:     "test",
			Commit:      "testcommit",
			SyftVersion: "pinned",
		},
		Host: host,
		Scan: model.ScanMeta{
			StartedAt:  fixedTime,
			FinishedAt: fixedTime,
			DurationMS: 0,
			// Record the fixture root as a stable literal rather than the
			// machine-specific absolute path.
			Root:       "testdata/rootfs",
			RanAsRoot:  false,
			Incomplete: result.Incomplete,
			Catalogers: result.Catalogers,
		},
		Components: model.Normalize(result.Components),
	}
}

// render writes the report in one format and returns the bytes, with the
// fixture's absolute path scrubbed so golden files are machine-independent.
func render(t *testing.T, format string, r *model.Report) []byte {
	t.Helper()
	writer, _, err := output.WriterFor(format)
	if err != nil {
		t.Fatalf("WriterFor(%q): %v", format, err)
	}
	var buf bytes.Buffer
	if err := writer(&buf, r); err != nil {
		t.Fatalf("writing %s: %v", format, err)
	}
	abs, _ := filepath.Abs("../../testdata/rootfs")
	return bytes.ReplaceAll(buf.Bytes(), []byte(abs), []byte("testdata/rootfs"))
}

// TestGolden is spec §12.2: scan the fixture rootfs and compare against
// checked-in golden JSON and CSV. Regenerate with `make golden`.
func TestGolden(t *testing.T) {
	report := scanFixture(t)

	for _, format := range []string{"json", "csv"} {
		t.Run(format, func(t *testing.T) {
			got := render(t, format, report)
			goldenPath := filepath.Join("..", "..", "testdata", "golden", "fixture."+format)

			if updateGolden {
				if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
					t.Fatalf("mkdir golden: %v", err)
				}
				if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
					t.Fatalf("writing golden: %v", err)
				}
				t.Logf("updated %s (%d bytes)", goldenPath, len(got))
				return
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("reading golden (run `make golden` to create it): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("output does not match %s\n--- got ---\n%s\n--- want ---\n%s",
					goldenPath, truncate(got), truncate(want))
			}
		})
	}
}

// TestFixtureContents asserts the fixture actually exercises the ecosystems we
// care about, so a golden file that silently went empty still fails.
func TestFixtureContents(t *testing.T) {
	report := scanFixture(t)

	byType := map[string]int{}
	for _, c := range report.Components {
		byType[c.Type]++
	}
	for _, want := range []string{"deb", "python", "npm"} {
		if byType[want] == 0 {
			t.Errorf("expected at least one %q component, got types %v", want, byType)
		}
	}

	// Every component must carry the canonical identifier.
	for _, c := range report.Components {
		if c.PURL == "" {
			t.Errorf("component %s@%s (%s) has no PURL", c.Name, c.Version, c.Type)
		}
	}

	if report.Host.OSID != "debian" {
		t.Errorf("OSID = %q, want debian (distro detection regressed)", report.Host.OSID)
	}
}

// TestDeterminism is spec §12.3: two scans of an unchanged tree must produce
// byte-identical output once the ScanMeta timestamps are blanked.
func TestDeterminism(t *testing.T) {
	first := scanFixture(t)
	second := scanFixture(t)

	// scanFixture already pins the timestamps; blank them again defensively so
	// this test states its own precondition.
	for _, r := range []*model.Report{first, second} {
		r.Scan.StartedAt = time.Time{}
		r.Scan.FinishedAt = time.Time{}
		r.Scan.DurationMS = 0
	}

	for _, format := range []string{"json", "csv", "ndjson", "cyclonedx-json"} {
		t.Run(format, func(t *testing.T) {
			a := render(t, format, first)
			b := render(t, format, second)
			if !bytes.Equal(a, b) {
				t.Errorf("%s output differs between two identical scans (%d vs %d bytes)",
					format, len(a), len(b))
			}
		})
	}
}

// TestSchemaShape checks the JSON actually matches the documented model.
func TestSchemaShape(t *testing.T) {
	report := scanFixture(t)
	raw := render(t, "json", report)

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, field := range []string{"schema_version", "tool", "host", "scan", "components"} {
		if _, ok := doc[field]; !ok {
			t.Errorf("missing top-level field %q", field)
		}
	}
	if doc["schema_version"] != model.SchemaVersion {
		t.Errorf("schema_version = %v, want %s", doc["schema_version"], model.SchemaVersion)
	}
}

// TestNonRoot is spec §12.4: the tool must succeed as a non-root user. The test
// suite does not run as root, so this asserts the run completes and records the
// expected warning rather than erroring out.
func TestNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test suite is running as root; nothing to assert")
	}

	dir := t.TempDir()
	root, err := filepath.Abs("../../testdata/rootfs")
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--root", root,
		"--out", dir,
		"--format", "json,csv",
		"--timeout", "5m",
		"--quiet",
	}, &stdout, &stderr)

	if code != exitOK && code != exitIncomplete {
		t.Fatalf("exit code = %d, want 0 or 1\nstderr: %s", code, stderr.String())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file %q left behind in output directory", e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatalf("no output files written to %s", dir)
	}

	// Find the JSON report and confirm the non-root warning is recorded.
	var found bool
	for _, n := range names {
		if !strings.HasSuffix(n, ".json") || strings.HasSuffix(n, ".cdx.json") {
			continue
		}
		full := filepath.Join(dir, n)
		if fi, err := os.Lstat(full); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		raw, err := os.ReadFile(full)
		if err != nil {
			t.Fatal(err)
		}
		var rep model.Report
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatalf("%s is not valid JSON: %v", n, err)
		}
		found = true
		if rep.Scan.RanAsRoot {
			t.Errorf("ran_as_root = true in a non-root test run")
		}
		if len(rep.Scan.Warnings) == 0 {
			t.Errorf("expected a warning recorded for the non-root run, got none")
		}
	}
	if !found {
		t.Errorf("no JSON report found among %v", names)
	}
}

func truncate(b []byte) string {
	const max = 3000
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "\n... (truncated)"
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}
