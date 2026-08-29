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

// openNonBlocking opens path O_RDONLY|O_NONBLOCK, following a final symlink but
// never blocking on a FIFO. O_NONBLOCK is a no-op for the regular files this
// package reads; the caller fstats the returned descriptor to reject anything
// that is not a regular file.
func openNonBlocking(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- path under the scan root; checked on the fd
}
