package main

import (
	"os"
	"testing"
)

func TestParseSize(t *testing.T) {
	ok := map[string]int64{
		"512MiB": 512 << 20, "512MB": 512 << 20, "512M": 512 << 20,
		"2GiB": 2 << 30, "2G": 2 << 30, "1KiB": 1024, "1024": 1024,
		"1.5GiB": 1610612736, " 2GiB ": 2 << 30, "2gib": 2 << 30,
	}
	for in, want := range ok {
		got, err := parseSize(in)
		if err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "-5MiB", "0", "MiB", "5XB"} {
		if _, err := parseSize(bad); err == nil {
			t.Errorf("parseSize(%q) should have failed", bad)
		}
	}
}

func TestParsePerm(t *testing.T) {
	ok := map[string]os.FileMode{
		"0644": 0o644, "644": 0o644, "0640": 0o640,
		"0600": 0o600, "0755": 0o755, " 0640 ": 0o640,
	}
	for in, want := range ok {
		got, err := parsePerm(in)
		if err != nil || got != want {
			t.Errorf("parsePerm(%q) = %o, %v; want %o", in, got, err, want)
		}
	}
	// Refused rather than silently masked: an inventory file has no business
	// carrying setuid/setgid/sticky, and one the owner cannot read is useless.
	for _, bad := range []string{"", "abc", "4755", "07777", "0244", "999"} {
		if _, err := parsePerm(bad); err == nil {
			t.Errorf("parsePerm(%q) should have failed", bad)
		}
	}
}

// TestDirPermFor: a directory needs execute wherever the file grants read, or
// the reports inside it cannot be reached.
func TestDirPermFor(t *testing.T) {
	cases := map[os.FileMode]os.FileMode{
		0o644: 0o755,
		0o640: 0o750,
		0o600: 0o700,
		0o664: 0o775,
		0o604: 0o705,
	}
	for file, want := range cases {
		if got := dirPermFor(file); got != want {
			t.Errorf("dirPermFor(%04o) = %04o, want %04o", file, got, want)
		}
	}
	// The owner must always keep write and execute or swinv cannot create the
	// files at all.
	for file := range cases {
		if d := dirPermFor(file); d&0o300 != 0o300 {
			t.Errorf("dirPermFor(%04o) = %04o, owner lost write or execute", file, d)
		}
	}
}
