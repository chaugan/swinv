//go:build !windows

package main

// helpOmittedFlags are registered but deliberately absent from this platform's
// help page.
//
// They stay registered rather than being compiled out, so that `swinv
// --usn-probe` on Linux answers "that only works on Windows" instead of Go's
// "flag provided but not defined". Someone following a Windows runbook on the
// wrong box deserves the honest refusal, not a parse error that reads like an
// out-of-date binary. The help footer says they exist.
func helpOmittedFlags() []string {
	return []string{"full-scan", "usn-probe", "volumes"}
}
