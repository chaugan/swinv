package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chaugan/swinv/internal/model"
)

func hbReport(components ...model.Component) *model.Report {
	return &model.Report{
		Host:       model.Host{Hostname: "web01"},
		Scan:       model.ScanMeta{StartedAt: time.Now().UTC()},
		Components: components,
	}
}

func hbConfig(dir string) *config {
	return &config{out: dir, filePerm: 0o644, dirPerm: 0o755, heartbeat: true, fullInterval: 24 * time.Hour}
}

var pkgA = model.Component{Name: "openssl", Version: "3.0.11", Type: "deb", Root: "/"}
var pkgB = model.Component{Name: "curl", Version: "8.5.0", Type: "deb", Root: "/"}

func quiet(string, ...any) {}

func TestHeartbeatLifecycle(t *testing.T) {
	dir := t.TempDir()
	cfg := hbConfig(dir)

	// First scan: nothing is known about this host, so everything is sent.
	first := hbReport(pkgA)
	applyHeartbeat(cfg, first, quiet)
	if first.Scan.InventoryUnchanged {
		t.Error("the first ever scan was reported as unchanged")
	}
	if first.Scan.InventoryDigest == "" {
		t.Fatal("no digest was computed")
	}

	// Second scan, same inventory: the heartbeat is the whole message.
	second := hbReport(pkgA)
	applyHeartbeat(cfg, second, quiet)
	if !second.Scan.InventoryUnchanged {
		t.Error("an unchanged inventory was reported as changed")
	}

	// A package appears.
	third := hbReport(pkgA, pkgB)
	applyHeartbeat(cfg, third, quiet)
	if third.Scan.InventoryUnchanged {
		t.Error("an added package did not force a full send")
	}

	// And disappears again. This is the case a delta cannot express, and the
	// reason the full list is resent rather than a diff.
	fourth := hbReport(pkgA)
	applyHeartbeat(cfg, fourth, quiet)
	if fourth.Scan.InventoryUnchanged {
		t.Error("a removed package did not force a full send")
	}
}

func TestHeartbeatForceFull(t *testing.T) {
	dir := t.TempDir()
	cfg := hbConfig(dir)
	applyHeartbeat(cfg, hbReport(pkgA), quiet)

	cfg.forceFull = true
	forced := hbReport(pkgA)
	applyHeartbeat(cfg, forced, quiet)
	if forced.Scan.InventoryUnchanged {
		t.Error("--force-full did not force a full send")
	}
}

// A digest collision, a hand-edited state file or a bug must not be able to
// hide a change indefinitely.
func TestHeartbeatFullInterval(t *testing.T) {
	dir := t.TempDir()
	cfg := hbConfig(dir)
	applyHeartbeat(cfg, hbReport(pkgA), quiet)

	cfg.fullInterval = time.Nanosecond
	stale := hbReport(pkgA)
	applyHeartbeat(cfg, stale, quiet)
	if stale.Scan.InventoryUnchanged {
		t.Error("the full-send interval elapsed and nothing was sent in full")
	}

	// Zero means never force one, for an operator who wants the digest to be
	// the only thing that decides.
	cfg.fullInterval = 0
	applyHeartbeat(cfg, hbReport(pkgA), quiet)
	never := hbReport(pkgA)
	applyHeartbeat(cfg, never, quiet)
	if !never.Scan.InventoryUnchanged {
		t.Error("--full-interval 0 forced a full send anyway")
	}
}

// Any problem reading the state means a full scan. Losing it costs one
// redundant send; trusting it wrongly costs a silent gap in what a fleet
// believes is installed.
func TestHeartbeatCorruptStateSendsEverything(t *testing.T) {
	dir := t.TempDir()
	cfg := hbConfig(dir)
	applyHeartbeat(cfg, hbReport(pkgA), quiet)

	if err := os.WriteFile(filepath.Join(dir, heartbeatStateFile), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := hbReport(pkgA)
	applyHeartbeat(cfg, after, quiet)
	if after.Scan.InventoryUnchanged {
		t.Error("a corrupt state file was trusted")
	}
}

// Two hosts writing to one output directory must not read each other's digest.
func TestHeartbeatIsPerHost(t *testing.T) {
	dir := t.TempDir()
	cfg := hbConfig(dir)
	applyHeartbeat(cfg, hbReport(pkgA), quiet)

	other := hbReport(pkgA)
	other.Host.Hostname = "web02"
	applyHeartbeat(cfg, other, quiet)
	if other.Scan.InventoryUnchanged {
		t.Error("a different host was reported as unchanged from another's digest")
	}
}

// Without the flag, nothing is computed and nothing is remembered.
func TestHeartbeatOffChangesNothing(t *testing.T) {
	dir := t.TempDir()
	cfg := hbConfig(dir)
	cfg.heartbeat = false

	r := hbReport(pkgA)
	applyHeartbeat(cfg, r, quiet)
	if r.Scan.InventoryDigest != "" || r.Scan.InventoryUnchanged {
		t.Errorf("scan meta was touched without --heartbeat: %+v", r.Scan)
	}
	if _, err := os.Stat(filepath.Join(dir, heartbeatStateFile)); err == nil {
		t.Error("a state file was written without --heartbeat")
	}
}

// The heartbeat is decided before the reports are written, so on the first
// scan into a fresh --out the directory does not exist yet. Without creating
// it, the state could never be written and every scan for ever would conclude
// that nothing was known.
func TestHeartbeatCreatesAFreshOutputDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist-yet")
	cfg := hbConfig(dir)

	first := hbReport(pkgA)
	applyHeartbeat(cfg, first, quiet)
	if len(first.Scan.Warnings) != 0 {
		t.Errorf("the first scan warned: %v", first.Scan.Warnings)
	}
	if _, err := os.Stat(filepath.Join(dir, heartbeatStateFile)); err != nil {
		t.Fatalf("no state file was written into a fresh output directory: %v", err)
	}

	second := hbReport(pkgA)
	applyHeartbeat(cfg, second, quiet)
	if !second.Scan.InventoryUnchanged {
		t.Error("the second scan did not see the first one's digest")
	}
}

// The state file must not look like a report to a collector globbing the
// output directory.
func TestHeartbeatStateFileIsHidden(t *testing.T) {
	if heartbeatStateFile[0] != '.' {
		t.Errorf("state file %q is not a dotfile and would be collected as a report", heartbeatStateFile)
	}
}
