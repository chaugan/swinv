package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

func tinyReport() *model.Report {
	return &model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.Tool{Name: "swinv", Version: "test"},
		Host:          model.Host{Hostname: "h"},
		Components:    []model.Component{{Name: "openssl", Version: "3", Type: "deb"}},
	}
}

// TestRenderHTMLReportOverwrites is the behaviour the field bug was about: a
// second write to an existing path must replace it, not silently leave the old
// file in place.
func TestRenderHTMLReportOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	if err := os.WriteFile(path, []byte("OLD-SENTINEL"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := renderHTMLReport(path, 0o644, tinyReport()); err != nil {
		t.Fatalf("renderHTMLReport: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "OLD-SENTINEL") {
		t.Fatal("existing file was not overwritten")
	}
	if len(got) < 1000 || !strings.HasPrefix(string(got), "<!doctype html>") {
		t.Fatalf("did not write the HTML report (got %d bytes, prefix %q)", len(got), safePrefix(got))
	}
}

// TestRenderHTMLReportRejectsDirectory turns what was a silent no-op on Windows
// into an error: a directory cannot be replaced by a file.
func TestRenderHTMLReportRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	err := renderHTMLReport(dir, 0o644, tinyReport())
	if err == nil {
		t.Fatal("expected an error for a directory target, got nil")
	}
	// And the file that would have been written must not be there.
	if _, statErr := os.Stat(filepath.Join(dir, "report.html")); statErr == nil {
		t.Fatal("a directory target must not produce a file inside it")
	}
}

// TestRenderHTMLReportCreatesParent lets a fresh nested path just work.
func TestRenderHTMLReportCreatesParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "report.html")
	if err := renderHTMLReport(path, 0o644, tinyReport()); err != nil {
		t.Fatalf("renderHTMLReport: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
		t.Fatalf("report not written to a fresh nested path: err=%v", err)
	}
}

func safePrefix(b []byte) string {
	if len(b) > 20 {
		b = b[:20]
	}
	return string(b)
}
