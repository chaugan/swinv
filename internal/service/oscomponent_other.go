//go:build !windows

package service

// IsOSComponent reports whether an executable belongs to the operating system.
//
// Always false away from Windows: on a Linux host the operating system's own
// binaries are owned by packages like any other, and the join finds them. A
// flag claiming otherwise would suppress real findings.
func IsOSComponent(string) bool { return false }

// pathsAreCaseInsensitive reports whether two recorded paths that differ only
// in case name the same file.
func pathsAreCaseInsensitive() bool { return false }
