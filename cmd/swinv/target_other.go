//go:build !windows

package main

// platformHandlesScan is false everywhere the filesystem is where installed
// software is recorded, which is everywhere swinv currently ships except
// Windows.
func platformHandlesScan() bool { return false }

// scanTarget is the root being walked.
func scanTarget(cfg *config) string { return cfg.root }
