package main

import (
	"runtime"
	"time"
)

// heartbeatInterval is how often a long scan reports that it is still alive.
// Long enough not to clutter a terminal, short enough that nobody concludes
// the process is wedged and kills it.
const heartbeatInterval = 30 * time.Second

// startHeartbeat emits a periodic "still scanning" line until the returned
// stop function is called.
//
// Between "scanning <root> ..." and the result line there is otherwise no
// output whatsoever, and a scan may legitimately run for the whole 30-minute
// deadline. A slow scan and a hung one therefore look identical, which is not
// a hypothetical: the first run of the Windows cross-compile against
// C:\Program Files was reported as "nothing is happening, it never finishes"
// while it was in fact working, blocked at 3% CPU on antivirus interception of
// every executable it opened.
//
// The elapsed time proves progress is being tracked and the deadline tells the
// operator the run is bounded, which is the specific reassurance missing when
// the decision is whether to wait or to hit Ctrl-C.
func startHeartbeat(quiet bool, deadline time.Duration, logf func(string, ...any)) func() {
	if quiet {
		return func() {}
	}

	done := make(chan struct{})
	stopped := make(chan struct{})

	go func() {
		defer close(stopped)
		start := time.Now()
		t := time.NewTicker(heartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				elapsed := time.Since(start).Round(time.Second)
				if deadline > 0 {
					logf("still scanning (%s elapsed, deadline %s)", elapsed, deadline)
					continue
				}
				logf("still scanning (%s elapsed)", elapsed)
			}
		}
	}()

	// Waiting on stopped keeps the goroutine from racing a later write to
	// stderr after the caller has moved on to printing results.
	return func() {
		close(done)
		<-stopped
	}
}

// resolveParallelism turns the --parallelism flag into a concrete worker count.
//
// An explicit value always wins, including a value larger than the CPU count:
// the bottleneck on a real scan is usually blocking I/O rather than CPU, so
// oversubscribing is a legitimate thing for an operator to ask for.
//
// Zero means "choose for me", and the choice depends on the mode. In the
// default background mode that is a quarter of the CPUs, because worker count
// sets the depth of the I/O queue this process presents to the kernel, and a
// shallow queue is most of what keeps a scan from making the rest of the
// machine feel slow. --fast uses every CPU, which is what the flag is for.
func resolveParallelism(requested int, fast bool) int {
	if requested > 0 {
		return requested
	}
	cpus := runtime.NumCPU()
	if fast {
		return cpus
	}
	if n := cpus / 4; n > 0 {
		return n
	}
	return 1
}
