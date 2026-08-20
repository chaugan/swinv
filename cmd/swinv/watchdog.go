package main

import (
	"fmt"
	"io"
	"os"
	"time"
)

// watchdogGrace is how long the cooperative path gets to unwind after the
// context deadline before the watchdog stops waiting for it.
const watchdogGrace = 10 * time.Second

// startDeadlineWatchdog terminates the process if the scan outlives its
// deadline, and returns a function that cancels it.
//
// --timeout is documented as a whole-run deadline, and until this existed it
// was not one. Syft's directory indexer walks the tree with filepath.Walk,
// which takes no context and checks no cancellation, so a scan stuck in
// indexing ignores the deadline entirely: a --timeout 5m run was observed still
// going at 5m30s with no sign of stopping. The context is only consulted at
// cataloger boundaries, which a stuck index never reaches.
//
// Exiting hard is not elegant, but a deadline that a caller cannot rely on is
// worse than no deadline at all. It is also safe here: reports are written by
// staging to a temp file and renaming, so terminating mid-run can leave debris
// beside the target but can never leave a half-written report in its place.
func startDeadlineWatchdog(timeout, grace time.Duration, stderr io.Writer) func() {
	if timeout <= 0 {
		return func() {}
	}

	done := make(chan struct{})
	go func() {
		t := time.NewTimer(timeout + grace)
		defer t.Stop()
		select {
		case <-done:
		case <-t.C:
			fmt.Fprintf(stderr,
				"swinv: timed out after %s and the scan did not stop when asked, so it was terminated.\n"+
					"       This happens when the deadline expires during filesystem indexing, which\n"+
					"       cannot be interrupted. Scan a narrower --root, or raise --timeout.\n",
				timeout)
			os.Exit(exitTimeout)
		}
	}()
	return func() { close(done) }
}
