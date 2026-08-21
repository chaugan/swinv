package main

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestResolveParallelism(t *testing.T) {
	cpus := runtime.NumCPU()

	t.Run("explicit wins over both modes", func(t *testing.T) {
		for _, fast := range []bool{false, true} {
			if got := resolveParallelism(7, fast); got != 7 {
				t.Errorf("fast=%v: got %d, want 7", fast, got)
			}
		}
	})

	t.Run("oversubscription is allowed", func(t *testing.T) {
		want := cpus * 4
		if got := resolveParallelism(want, false); got != want {
			t.Errorf("got %d, want %d: a scan blocked on I/O may legitimately want more workers than CPUs", got, want)
		}
	})

	t.Run("fast uses every CPU", func(t *testing.T) {
		if got := resolveParallelism(0, true); got != cpus {
			t.Errorf("got %d, want %d", got, cpus)
		}
	})

	t.Run("background uses a quarter, never zero", func(t *testing.T) {
		got := resolveParallelism(0, false)
		if got < 1 {
			t.Fatalf("got %d: a worker count below 1 would stall the scan entirely", got)
		}
		if want := cpus / 4; want > 0 && got != want {
			t.Errorf("got %d, want %d", got, want)
		}
		if got > cpus {
			t.Errorf("got %d, want no more than %d: background mode must never exceed --fast", got, cpus)
		}
	})
}

// TestHeartbeatQuietStillDumpsStacks pins a bug where --quiet silently
// disabled --debug-stacks-after. The dump timer lived inside the heartbeat
// goroutine, and --quiet skipped the goroutine entirely, so an operator
// debugging a hung scheduled task -- which is where both flags get used
// together -- got no dump and no explanation.
func TestHeartbeatQuietStillDumpsStacks(t *testing.T) {
	dir := t.TempDir()
	var logged int
	logf := func(string, ...any) { logged++ }

	stop := startHeartbeat(true, time.Minute, 10*time.Millisecond, dir, logf)
	time.Sleep(300 * time.Millisecond)
	stop()

	matches, err := filepath.Glob(filepath.Join(dir, "swinv-stacks-*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("got %d dump files, want 1: --quiet must not disable an explicitly requested diagnostic", len(matches))
	}
	if logged != 0 {
		t.Errorf("logged %d times under --quiet, want 0: the file is written, the chatter is not", logged)
	}
}

// TestHeartbeatQuietWithoutStacksDoesNothing checks the ordinary quiet case
// still starts no goroutine and says nothing.
func TestHeartbeatQuietWithoutStacksDoesNothing(t *testing.T) {
	dir := t.TempDir()
	var logged int

	stop := startHeartbeat(true, time.Minute, 0, dir, func(string, ...any) { logged++ })
	time.Sleep(50 * time.Millisecond)
	stop()

	if logged != 0 {
		t.Errorf("logged %d times, want 0", logged)
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "swinv-stacks-*.txt")); len(matches) != 0 {
		t.Errorf("wrote %d dump files without being asked", len(matches))
	}
}
