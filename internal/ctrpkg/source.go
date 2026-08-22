package ctrpkg

import (
	"os"
	"path/filepath"
)

// Source is a container's filesystem, however it is reached.
//
// Two implementations exist because the two ways in are not interchangeable.
// A running container on Linux is readable directly through /proc/<pid>/root,
// which is free and needs no daemon. A stopped container has no process, and
// on Windows there is no /proc at all, so the only way in is to ask the
// runtime for the file -- which works in both states and on both platforms,
// at the cost of talking to a daemon.
type Source interface {
	// ReadFile returns one file's contents.
	ReadFile(path string) ([]byte, error)

	// ReadDir returns the regular files directly inside a directory, keyed by
	// their base name. Used for dpkg's per-package file lists.
	ReadDir(path string) (map[string][]byte, error)

	// IsSymlink reports whether a top-level directory is a symlink, which is
	// what decides whether /bin and /usr/bin name the same files.
	IsSymlink(path string) bool
}

// DirSource reads a container's filesystem from a directory, which is what
// /proc/<pid>/root is.
type DirSource struct{ Root string }

func (d DirSource) ReadFile(name string) ([]byte, error) {
	return readCapped(filepath.Join(d.Root, filepath.FromSlash(name)))
}

func (d DirSource) ReadDir(name string) (map[string][]byte, error) {
	dir := filepath.Join(d.Root, filepath.FromSlash(name))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		content, err := readCapped(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		out[e.Name()] = content
	}
	return out, nil
}

func (d DirSource) IsSymlink(name string) bool {
	fi, err := os.Lstat(filepath.Join(d.Root, filepath.FromSlash(name)))
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}
