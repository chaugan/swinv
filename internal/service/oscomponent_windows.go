//go:build windows

package service

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	// The kernel process, which serves SMB and NetBIOS and has no image path.
	if exe == systemProcessName {
		return true
	}
	// %SystemRoot% is a constant; recomputing and re-lowering it per call
	// allocated four strings for every one of the hundreds of thousands of
	// DLL paths the link probe asks about.
	osRootOnce.Do(func() {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		osRootLower = strings.ToLower(filepath.Clean(root))
	})
	candidate := strings.ToLower(filepath.Clean(exe))
	return candidate == osRootLower ||
		strings.HasPrefix(candidate, osRootLower) &&
			len(candidate) > len(osRootLower) && candidate[len(osRootLower)] == filepath.Separator
}

var (
	osRootOnce  sync.Once
	osRootLower string
)

// pathsAreCaseInsensitive reports whether two recorded paths that differ only
// in case name the same file. They do on Windows, and the registry and the
// process table disagree about case often enough to matter.
func pathsAreCaseInsensitive() bool { return true }
