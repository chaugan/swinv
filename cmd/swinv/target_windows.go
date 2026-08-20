//go:build windows

package main

import "fmt"

// platformHandlesScan reports that this platform collects its inventory some
// way other than by walking the filesystem, so the exclusion machinery -- mount
// tables, layout exclusions, symlink preflight -- has nothing to act on and
// should not run.
func platformHandlesScan() bool { return true }

// scanTarget describes what is about to be inventoried, for the log line.
//
// On Windows "/" is not the answer to any question. The record of installed
// software is the registry; the filesystem is consulted only under --full-scan,
// and then per volume.
func scanTarget(cfg *config) string {
	if !cfg.fullScan {
		return "the uninstall registry"
	}
	if cfg.volumes != "" {
		return fmt.Sprintf("the uninstall registry and volumes %s", cfg.volumes)
	}
	return "the uninstall registry and volume C:"
}
