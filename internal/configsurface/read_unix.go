//go:build unix

package configsurface

import (
	"os"
	"syscall"
)

// fileUID returns the owning uid of an already-stat'd file. Unix only; on
// other platforms the ownership gate is skipped (Windows has its own model,
// handled elsewhere).
func fileUID(fi os.FileInfo) (uint32, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid, true
	}
	return 0, false
}

// suidOwner returns the owning uid of a walked file for the SUID collector.
func suidOwner(fi os.FileInfo) (uint32, bool) { return fileUID(fi) }
