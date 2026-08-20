//go:build !windows

package output

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// syncDir fsyncs a directory so that a rename into it survives a power loss.
// Without it the file contents are durable but the directory entry pointing at
// them may not be, which is exactly the window an atomic write exists to close.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("output: opening directory %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		// Some filesystems simply do not implement directory fsync. The data
		// and the rename are already in place, so this is not a failure.
		// EINVAL is what Linux returns for a directory on such a filesystem;
		// errors.ErrUnsupported covers the ENOTSUP/EOPNOTSUPP spellings.
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, fs.ErrPermission) ||
			errors.Is(err, errors.ErrUnsupported) {
			return nil
		}
		return fmt.Errorf("output: syncing directory %s: %w", dir, err)
	}
	return nil
}
