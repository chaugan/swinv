package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"

	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/output"
)

func TestScanningLiveHost(t *testing.T) {
	live := []string{"", "/", "/.", "//"}
	for _, in := range live {
		if !scanningLiveHost(in) {
			t.Errorf("scanningLiveHost(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"/mnt/image", "./rootfs", "/snap/core22/current"} {
		if scanningLiveHost(in) {
			t.Errorf("scanningLiveHost(%q) = true; the sockets open now belong to the host, not that tree", in)
		}
	}
}

func servicesFixture() *model.Report {
	return &model.Report{
		SchemaVersion: model.SchemaVersion,
		Host:          model.Host{Hostname: "web01"},
		Services: []model.Service{{
			Endpoints:  []string{"0.0.0.0:22/tcp"},
			PID:        811,
			Executable: "/usr/sbin/sshd",
			Confidence: model.ConfidenceHigh,
		}},
	}
}

func TestWriteServicesCSVSidecar(t *testing.T) {
	dir := t.TempDir()
	cfg := &config{out: dir, filePerm: 0o644, latestSymlink: true}
	report := servicesFixture()

	if code := writeServicesCSV(cfg, report, "web01-20240102", func(string, ...any) {}, os.Stderr); code != exitOK {
		t.Fatalf("writeServicesCSV returned %d", code)
	}

	target := filepath.Join(dir, "web01-20240102-services.csv")
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("reading sidecar: %v", err)
	}
	rows, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil {
		t.Fatalf("sidecar is not valid CSV: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("got %d rows, want header + 1", len(rows))
	}
	if len(rows[0]) != len(output.ServiceCSVColumns()) {
		t.Errorf("header has %d columns, want %d", len(rows[0]), len(output.ServiceCSVColumns()))
	}

	// The -latest name is what a collector picks up, and it has to point at
	// the services file rather than at the components one.
	link := filepath.Join(dir, "web01-latest-services.csv")
	dest, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("reading %s: %v", link, err)
	}
	if dest != "web01-20240102-services.csv" {
		t.Errorf("symlink points at %q", dest)
	}
}

// No services block means services were never collected -- Windows, or
// --no-services. An empty sidecar there would claim the scan looked and found
// nothing listening, which is a different and false statement.
func TestWriteServicesCSVSkippedWhenNotCollected(t *testing.T) {
	dir := t.TempDir()
	cfg := &config{out: dir, filePerm: 0o644}
	report := servicesFixture()
	report.Services = nil

	if code := writeServicesCSV(cfg, report, "web01", func(string, ...any) {}, os.Stderr); code != exitOK {
		t.Fatalf("writeServicesCSV returned %d", code)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("wrote %v, want nothing", entries)
	}
}

func TestSummariseServices(t *testing.T) {
	got := summariseServices([]model.Service{
		{Confidence: model.ConfidenceHigh},
		{Confidence: model.ConfidenceHigh},
		{Confidence: model.ConfidenceMedium},
		{Confidence: model.ConfidenceLow},
	})
	want := "2 attributed to installed software, 1 running software nothing installed, 1 unidentified"
	if got != want {
		t.Errorf("summariseServices = %q, want %q", got, want)
	}
}
