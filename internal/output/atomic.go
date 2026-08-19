package output

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

// tempSuffix builds the staging name for path: "<path>.tmp-<pid>" in the same
// directory as path, so the final rename is within one filesystem and is
// therefore atomic, and so a crash leaves the debris next to its target where
// it is obvious.
func tempSuffix(path string) string {
	return path + ".tmp-" + strconv.Itoa(os.Getpid())
}

// clearStaleTemp removes debris left at the legacy "<target>.tmp-<pid>" name by
// an earlier crashed run that happened to share this PID. Remove never follows
// symlinks, so this cannot be redirected somewhere else.
func clearStaleTemp(target string) error {
	if err := os.Remove(tempSuffix(target)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("output: removing stale temp file %s: %w", tempSuffix(target), err)
	}
	return nil
}

// AtomicWriteFile writes a file by staging it alongside its target and
// renaming it into place, so that a reader never observes a partial file and
// an existing file is only ever replaced by a complete one.
//
// The sequence is: create <path>.tmp-<pid> in the same directory, let fn write
// to it, flush, fsync the file, set its mode to perm, close it, rename it onto
// path, and finally fsync the containing directory so the rename itself
// survives a power loss. On any failure — including a panic inside fn — the
// temporary file is removed and path is left exactly as it was.
//
// perm is applied explicitly rather than left to the process umask, so a
// caller asking for 0644 gets 0644.
func AtomicWriteFile(path string, perm os.FileMode, fn func(io.Writer) error) error {
	if fn == nil {
		return errors.New("output: nil write function")
	}

	dir := filepath.Dir(path)
	if err := clearStaleTemp(path); err != nil {
		return err
	}

	// os.CreateTemp guarantees a name no other writer holds, which the PID
	// alone does not: two writers inside one process, or a live process that
	// reused this PID, would otherwise collide on the same staging file. It
	// also creates O_EXCL, so a pre-existing symlink cannot redirect the write.
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("output: creating temp file next to %s: %w", path, err)
	}
	tmp := f.Name()

	// Until the rename succeeds, every exit path must leave nothing behind.
	committed := false
	closed := false
	defer func() {
		if committed {
			return
		}
		if !closed {
			_ = f.Close()
		}
		_ = os.Remove(tmp)
	}()

	bw := bufio.NewWriterSize(f, 64*1024)
	if err := fn(bw); err != nil {
		return fmt.Errorf("output: writing %s: %w", tmp, err)
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("output: flushing %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("output: syncing %s: %w", tmp, err)
	}
	// Chmod on the open descriptor rather than the path: it cannot be raced
	// and it undoes any umask restriction applied at creation.
	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("output: setting mode on %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		closed = true
		return fmt.Errorf("output: closing %s: %w", tmp, err)
	}
	closed = true

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("output: renaming %s to %s: %w", tmp, path, err)
	}
	committed = true

	if err := syncDir(dir); err != nil {
		return err
	}
	return nil
}

// UpdateSymlink points linkPath at target atomically, by creating a temporary
// symlink in the same directory and renaming it over linkPath. A reader
// following the link therefore sees either the old target or the new one,
// never a missing link.
//
// When target sits in the same directory as linkPath it is stored as a bare
// basename, which keeps the link valid if the directory is moved or is mounted
// at a different path on the machine that later reads it.
func UpdateSymlink(linkPath, target string) error {
	if linkPath == "" {
		return errors.New("output: empty symlink path")
	}
	if target == "" {
		return errors.New("output: empty symlink target")
	}

	dir := filepath.Dir(linkPath)
	if filepath.IsAbs(target) && filepath.Dir(target) == filepath.Clean(dir) {
		target = filepath.Base(target)
	}

	tmp := tempSuffix(linkPath)
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("output: removing stale temp symlink %s: %w", tmp, err)
	}
	if err := os.Symlink(target, tmp); err != nil {
		return fmt.Errorf("output: creating temp symlink %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, linkPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("output: renaming symlink %s to %s: %w", tmp, linkPath, err)
	}
	return syncDir(dir)
}

// syncDir fsyncs a directory so that a rename performed inside it is durable.
// A filesystem that refuses to open a directory for reading, or that does not
// implement directory fsync, is not an error: the data is already in place.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("output: opening directory %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		if errors.Is(err, fs.ErrInvalid) || errors.Is(err, fs.ErrPermission) {
			return nil
		}
		return fmt.Errorf("output: syncing directory %s: %w", dir, err)
	}
	return nil
}
