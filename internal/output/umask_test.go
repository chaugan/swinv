//go:build !windows

package output

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// syscallUmask sets the process umask and returns the previous value. It lives
// in its own file so the one Unix-only call in the tests is easy to find.
func syscallUmask(mask int) int { return syscall.Umask(mask) }

func TestAtomicWriteFileModeIsIndependentOfUmask(t *testing.T) {
	old := syscallUmask(0o077)
	defer syscallUmask(old)

	dir := t.TempDir()
	path := filepath.Join(dir, "wide.csv")
	if err := AtomicWriteFile(path, 0o644, func(w io.Writer) error { return nil }); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %o, want %o even under a restrictive umask", perm, 0o644)
	}
}
