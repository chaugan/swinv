// Package sched lowers this process's scheduling priority so that taking an
// inventory does not degrade the machine being inventoried.
//
// The trade this package encodes is deliberate: a scan that takes twice as long
// but leaves the system responsive is better than a fast one that makes an
// interactive session stutter or starves a database of I/O. An inventory
// collector is background maintenance. It runs unattended, on a timer, on
// machines doing real work, and nobody is waiting on its result.
//
// The cost is real and is not hidden: background mode makes scans slower,
// sometimes considerably, and --fast exists for the operator who would rather
// have the answer now.
package sched

import (
	"fmt"
	"runtime"
)

// Mode selects how aggressively the scan competes with everything else for the
// machine.
type Mode int

const (
	// Background lowers CPU and I/O scheduling priority. The default.
	Background Mode = iota
	// Normal leaves scheduling priority untouched, so the scan competes on
	// equal terms with interactive work.
	Normal
)

// Apply adjusts the current process's scheduling priority for the given mode.
//
// It returns notes describing what was actually applied, for --verbose, and
// warnings for anything that could not be. Neither is fatal: failing to become
// polite is a reason to say so, not a reason to refuse to take an inventory.
func Apply(mode Mode) (notes, warnings []string) {
	if mode == Normal {
		return nil, nil
	}

	// The politeness promise covers the whole process for the whole run,
	// and OS scheduling priority alone does not keep it: the Go garbage
	// collector runs on every processor the runtime can see, and the phases
	// that allocate hard - serializing a few hundred thousand link records
	// was the one that got reported as "HAMMERING the system" - turn into
	// synchronized all-core bursts that priority softens but does not
	// shrink. Capping the runtime at a quarter of the machine bounds
	// everything at once: workers, encoders, and the collector behind them.
	limit := runtime.NumCPU() / 4
	if limit < 2 {
		limit = 2
	}
	prev := runtime.GOMAXPROCS(limit)
	if limit < prev {
		notes = append(notes, fmt.Sprintf(
			"runtime limited to %d of %d processors, garbage collector included; --fast lifts it",
			limit, prev))
	}

	n, w := background()
	return append(notes, n...), w
}
