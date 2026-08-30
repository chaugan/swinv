package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// The tests here cover the run-level output-directory guard: which runs pull
// the directory in at all, that the guard creates (and only creates) what it
// should, and that the heartbeat state writer no longer creates the directory
// itself -- the property whose absence let a plain MkdirAll on Windows hand a
// SYSTEM run's output directory an inherited, user-readable ACL.

func TestOutputDirUsedBy(t *testing.T) {
	cases := []struct {
		name string
		cfg  config
		want bool
	}{
		{"stdout, nothing else touches no directory", config{toStdout: true}, false},
		{"file output pulls the directory in", config{}, true},
		{"stdout plus heartbeat writes state", config{toStdout: true, heartbeat: true}, true},
		{"stdout plus transmit writes the spool", config{toStdout: true, transmit: "https://collector.example"}, true},
		{"stdout plus a stacks dump writes mid-scan", config{toStdout: true, stacksAfter: time.Minute}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := outputDirUsedBy(&tc.cfg); got != tc.want {
				t.Errorf("outputDirUsedBy(%+v) = %v, want %v", tc.cfg, got, tc.want)
			}
		})
	}
}

func TestEnsureOutputDirCreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "swinv-out")
	cfg := &config{out: dir, filePerm: 0o600, dirPerm: dirPermFor(0o600)}

	if code := ensureOutputDir(cfg, os.Stderr); code != exitOK {
		t.Fatalf("ensureOutputDir returned exit code %d, want %d", code, exitOK)
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		t.Fatalf("ensureOutputDir did not leave a directory at %s: %v", dir, err)
	}
	// A second run over the same directory must stay a success: the guard
	// runs on every scan, and the normal case is a directory that already
	// exists with yesterday's reports in it.
	if code := ensureOutputDir(cfg, os.Stderr); code != exitOK {
		t.Fatalf("second ensureOutputDir returned exit code %d, want %d", code, exitOK)
	}
	if runtime.GOOS != "windows" {
		// POSIX modes are inert on Windows; there the DACL governs instead.
		if got := fi.Mode().Perm(); got != cfg.dirPerm {
			t.Errorf("directory mode is %04o, want %04o", got, cfg.dirPerm)
		}
	}
}

func TestEnsureOutputDirCreatesMissingParents(t *testing.T) {
	// The shipped default is a nested path that does not exist after install:
	// the guard, not the operator, is what makes `--out /var/lib/swinv` or
	// C:\var\lib\swinv work on a machine where the parents are absent.
	dir := filepath.Join(t.TempDir(), "var", "lib", "swinv")
	cfg := &config{out: dir, filePerm: 0o644, dirPerm: dirPermFor(0o644)}

	if code := ensureOutputDir(cfg, os.Stderr); code != exitOK {
		t.Fatalf("ensureOutputDir returned exit code %d, want %d", code, exitOK)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("ensureOutputDir did not create the nested path %s: %v", dir, err)
	}
}

func TestEnsureOutputDirFailsOnAnUnwritablePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory modes cannot make a path unwritable on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: an unwritable directory cannot be staged")
	}
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.Mkdir(blocker, 0o500); err != nil {
		t.Fatal(err)
	}
	cfg := &config{out: filepath.Join(blocker, "swinv"), filePerm: 0o600, dirPerm: 0o700}

	if code := ensureOutputDir(cfg, os.Stderr); code != exitFatal {
		t.Errorf("ensureOutputDir into an unwritable parent returned %d, want %d", code, exitFatal)
	}
}

// TestWriteHeartbeatStateDoesNotCreateTheDirectory is the W1 regression test.
//
// writeHeartbeatState used to MkdirAll the output directory itself. On
// Windows that plain MkdirAll could run before secureOutputDir -- or run
// where secureOutputDir never would, on a --stdout run -- creating --out with
// the parent's inherited ACLs and voiding the admin-only DACL the guard is
// supposed to guarantee. The writer must now fail into a missing directory,
// and the failure must degrade to the warning applyHeartbeat already carries,
// not create anything.
func TestWriteHeartbeatStateDoesNotCreateTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")

	err := writeHeartbeatState(dir, 0o600, heartbeatState{})
	if err == nil {
		t.Fatal("writeHeartbeatState into a missing directory succeeded; it must fail instead")
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Errorf("the missing directory was created anyway: %v", statErr)
	}

	// Through applyHeartbeat, the same failure is a warning on the report and
	// an unchanged exit, because losing the digest costs one redundant full
	// send and nothing more.
	cfg := hbConfig(dir)
	report := hbReport(pkgA)
	applyHeartbeat(cfg, report, quiet)
	if report.Scan.InventoryUnchanged {
		t.Error("a scan whose digest could not be recorded reported itself unchanged")
	}
	if len(report.Scan.Warnings) == 0 {
		t.Error("no warning was recorded for the unwritable heartbeat state")
	}
}
