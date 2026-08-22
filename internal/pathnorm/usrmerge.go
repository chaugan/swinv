// Package pathnorm normalises filesystem paths so that two sources describing
// the same file agree about its name.
package pathnorm

import (
	"os"
	"path/filepath"
	"strings"
)

// mergedUsrDirs are the top-level directories the /usr merge turned into
// symlinks into /usr.
var mergedUsrDirs = []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"}

// UsrMerge builds the canonicalisation that lets a package's recorded file
// list be compared against a path the kernel reported.
//
// The two disagree about the same file. dpkg on Ubuntu 24.04 records
// netcat-openbsd as owning /bin/nc.openbsd, while /proc/<pid>/exe reports the
// running process as /usr/bin/nc.openbsd: the kernel resolves the merge
// symlink, the package database preserves the path from before the merge. A
// plain comparison misses, and the running process is reported as software no
// package manager installed -- a confident wrong answer about a file that is
// very much installed.
//
// Whether each directory is a symlink is checked rather than assumed, because
// /bin is a real directory on Alpine, where /bin/busybox and /usr/bin/busybox
// are different files and folding them together would invent a match rather
// than find one.
func UsrMerge(root string) func(string) string {
	merged := make(map[string]bool, len(mergedUsrDirs))
	for _, d := range mergedUsrDirs {
		if fi, err := os.Lstat(filepath.Join(root, d)); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			merged[d] = true
		}
	}
	if len(merged) == 0 {
		return func(p string) string { return p }
	}
	return func(p string) string {
		rest, ok := strings.CutPrefix(p, "/")
		if !ok {
			return p
		}
		first, _, ok := strings.Cut(rest, "/")
		if !ok || !merged[first] {
			return p
		}
		return "/usr" + p
	}
}
