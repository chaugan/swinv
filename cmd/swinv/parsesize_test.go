package main

import "testing"

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
