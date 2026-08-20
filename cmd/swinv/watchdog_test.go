package main

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestDeadlineWatchdogTerminates checks that the watchdog actually kills a run
// that ignores its deadline. It has to re-exec itself, because the behaviour
// under test is os.Exit and there is no way to observe that in-process.
//
// This matters more than the usual belt-and-braces test: the cooperative path
// handles the deadline whenever Syft reaches a cancellation check, which on
// Linux it almost always does. The watchdog only ever runs in the case that is
// hard to reproduce deliberately -- a scan wedged inside filesystem indexing,
// which is exactly where a Windows host was observed running 30 seconds past a
// 5-minute deadline. Without this test the code path would ship unexercised.
func TestDeadlineWatchdogTerminates(t *testing.T) {
	if os.Getenv("SWINV_WATCHDOG_CHILD") == "1" {
		startDeadlineWatchdog(10*time.Millisecond, 40*time.Millisecond, os.Stderr)
		// Stand in for a scan that never checks for cancellation.
		select {}
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestDeadlineWatchdogTerminates$")
	cmd.Env = append(os.Environ(), "SWINV_WATCHDOG_CHILD=1")

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting child: %v", err)
	}
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		var code int
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		if code != exitTimeout {
			t.Fatalf("child exited with %d (err %v), want %d", code, err, exitTimeout)
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("watchdog did not terminate the child: a deadline callers cannot rely on is worse than none")
	}
}

// TestDeadlineWatchdogCancels checks the watchdog does not fire once the scan
// has finished, which would turn a successful run into a spurious timeout.
func TestDeadlineWatchdogCancels(t *testing.T) {
	stop := startDeadlineWatchdog(10*time.Millisecond, 20*time.Millisecond, os.Stderr)
	stop()
	// If the watchdog were still armed it would call os.Exit here and take the
	// whole test binary down with it.
	time.Sleep(200 * time.Millisecond)
}

// TestDeadlineWatchdogDisabled checks that a non-positive timeout arms nothing.
func TestDeadlineWatchdogDisabled(t *testing.T) {
	stop := startDeadlineWatchdog(0, time.Millisecond, os.Stderr)
	defer stop()
	time.Sleep(50 * time.Millisecond)
}
