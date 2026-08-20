//go:build windows

package usn

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func isExecutable(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".exe", ".dll", ".sys", ".ocx", ".cpl", ".drv":
		return true
	}
	return false
}

// TestEnumerateSystemVolume is the whole point of the package, measured against
// a real volume. It reports its numbers with t.Log rather than only asserting,
// because the ratio of executables to total records is the figure that decides
// whether MFT enumeration is worth having over a directory walk.
func TestEnumerateSystemVolume(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	start := time.Now()
	res, err := Enumerate(ctx, Options{
		Volume: "C:",
		Keep:   func(name string, isDir bool, _ uint32) bool { return !isDir && isExecutable(name) },
	})
	elapsed := time.Since(start)

	if errors.Is(err, ErrNotElevated) {
		t.Skip("not elevated: FSCTL_ENUM_USN_DATA needs an elevated token")
	}
	if errors.Is(err, ErrNotNTFS) {
		t.Skip("C: is not NTFS")
	}
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	t.Logf("MFT records read:      %d", res.Records)
	t.Logf("directories held:      %d", res.Directories)
	t.Logf("executables kept:      %d", len(res.Entries))
	t.Logf("unresolved paths:      %d", res.Unresolved)
	t.Logf("elapsed:               %s", elapsed.Round(time.Millisecond))
	if res.Records > 0 {
		t.Logf("kept fraction:         %.1f%%  <- files a directory walk would have opened and this did not",
			100*float64(len(res.Entries))/float64(res.Records))
	}

	if res.Records == 0 {
		t.Fatal("read zero MFT records from C:, which cannot be right")
	}
	if len(res.Entries) == 0 {
		t.Fatal("found no executables on C:, which cannot be right")
	}

	// Unresolved paths are expected in small numbers on a live filesystem, but
	// a large fraction means path reconstruction is broken rather than racing.
	if frac := float64(res.Unresolved) / float64(len(res.Entries)); frac > 0.05 {
		t.Errorf("%.1f%% of entries have no path (%d of %d); a live filesystem should race on a handful, not this many",
			100*frac, res.Unresolved, len(res.Entries))
	}
}

// TestEnumerateFindsAKnownFile checks path reconstruction against a file that
// exists on every Windows installation. Getting a plausible but wrong path is
// the failure mode that matters, so this asserts the exact path rather than
// merely that something was found.
func TestEnumerateFindsAKnownFile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	res, err := Enumerate(ctx, Options{
		Volume: "C:",
		Keep: func(name string, isDir bool, _ uint32) bool {
			return !isDir && strings.EqualFold(name, "kernel32.dll")
		},
	})
	if errors.Is(err, ErrNotElevated) {
		t.Skip("not elevated")
	}
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	want := strings.ToLower(`c:\windows\system32\kernel32.dll`)
	for _, e := range res.Entries {
		if strings.ToLower(e.Path) == want {
			t.Logf("found %s among %d copies of kernel32.dll", e.Path, len(res.Entries))
			return
		}
	}

	for _, e := range res.Entries {
		t.Logf("  saw %q", e.Path)
	}
	t.Fatalf("did not find %s among %d entries", want, len(res.Entries))
}

func TestEnumerateRejectsBadVolume(t *testing.T) {
	for _, bad := range []string{"", "C", `\\server\share`, `C:\Windows`} {
		if _, err := Enumerate(context.Background(), Options{Volume: bad}); err == nil {
			t.Errorf("Enumerate(%q) succeeded; want a usage error", bad)
		}
	}
}

// TestEnumerateHonoursContext checks that a cancelled scan stops. An
// enumeration of a large volume runs for a while, and --timeout has to be able
// to end it -- the lesson from a Windows scan that ran past its deadline
// because filepath.Walk consults no context.
func TestEnumerateHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Enumerate(ctx, Options{Volume: "C:"})
	if errors.Is(err, ErrNotElevated) || errors.Is(err, ErrNotNTFS) {
		t.Skip("cannot enumerate C: here")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
