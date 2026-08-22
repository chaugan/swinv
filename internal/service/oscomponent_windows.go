//go:build windows

package service

import (
	"os"
	"path/filepath"
	"strings"
)

// IsOSComponent reports whether an executable belongs to the operating system.
//
// On Windows this matters for the report's honesty. swinv deliberately does
// not inventory operating-system components file by file -- 53,559 of them on
// one real machine -- and represents them by the installed servicing updates
// instead. So a service running from C:\Windows\System32 has no owning
// component and never will, and calling that "software nothing installed"
// would describe the operating system as an unmanaged binary somebody dropped
// on the host.
func IsOSComponent(exe string) bool {
	if exe == "" {
		return false
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	root = strings.ToLower(filepath.Clean(root))
	candidate := strings.ToLower(filepath.Clean(exe))
	return candidate == root || strings.HasPrefix(candidate, root+string(filepath.Separator))
}

// pathsAreCaseInsensitive reports whether two recorded paths that differ only
// in case name the same file. They do on Windows, and the registry and the
// process table disagree about case often enough to matter.
func pathsAreCaseInsensitive() bool { return true }
