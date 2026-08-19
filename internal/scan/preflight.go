package scan

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/chaugan/swinv/internal/model"
)

// maxQuarantineWarnings caps how many individual symlinks a warning names.
const maxQuarantineWarnings = 5

// QuarantineSymlinks finds symlinks whose target swinv cannot resolve and
// returns exclusion patterns for the symlinks themselves.
//
// This works around a hard failure mode in Syft's directory indexer. When the
// indexer meets a symlink it queues the link's target as an *additional root*
// to index (addSymlinkToIndex returns the target unless os.Stat reports
// ENOENT). Each additional root is then passed to indexTree, which resolves it
// with filepath.EvalSymlinks before any path-index visitor runs. If that
// resolution fails — the common case being a symlink into another user's home
// directory when swinv runs unprivileged — indexAllRoots treats the error as
// fatal and CreateSBOM returns nothing at all. A five-minute scan yields zero
// components because of one unreadable symlink.
//
// Crucially, excluding the *target* does not help: the exclusion visitors run
// inside indexPath, strictly after the fatal resolution. Verified on a live
// host — excluding "./root/**" still failed on
// "/opt/.../.venv12/bin/python -> /root/.local/.../python3.12". The only thing
// that prevents the failure is excluding the *link* so the indexer never
// queues its target.
//
// The walk is lstat-only: it never opens or reads a file, and it never follows
// a symlink, so it is far cheaper than the cataloging walk that follows. It
// honours the exclusion patterns already computed so it does not descend into
// trees the scan will skip anyway.
//
// Errors are never fatal. An unreadable directory is skipped silently — it is
// not something the operator can act on and the scan is still correct.
func QuarantineSymlinks(ctx context.Context, root string, excludes []string) (patterns []string, warnings []string) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, nil
	}
	absRoot = path.Clean(filepath.ToSlash(absRoot))

	matchers := absoluteMatchers(absRoot, excludes)

	var quarantined []string
	walkErr := filepath.WalkDir(absRoot, func(p string, d fs.DirEntry, err error) error {
		// Cancellation must stop the preflight promptly; the caller will
		// surface the context error from the scan proper.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			// An unreadable directory is expected when running unprivileged.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		slashed := filepath.ToSlash(p)
		if d.IsDir() {
			if slashed != absRoot && matchesAny(matchers, slashed) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		if matchesAny(matchers, slashed) {
			return nil
		}

		if !symlinkTargetResolvable(p) {
			rel, ok := relativeTo(absRoot, slashed)
			if !ok {
				return nil
			}
			quarantined = append(quarantined, "./"+escapeGlobMeta(rel))
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, context.Canceled) && !errors.Is(walkErr, context.DeadlineExceeded) {
		warnings = append(warnings, fmt.Sprintf(
			"symlink preflight did not complete (%v); a symlink pointing at an unreadable path may abort cataloging", walkErr))
	}

	if len(quarantined) == 0 {
		return nil, warnings
	}

	patterns = model.SortedSet(quarantined)
	warnings = append(warnings, fmt.Sprintf(
		"excluded %d symlink(s) whose target could not be resolved (usually another user's home directory); "+
			"software reachable only through them is not in this inventory: %s",
		len(patterns), summarizeList(truncateList(patterns, maxQuarantineWarnings))))
	return patterns, warnings
}

// symlinkTargetResolvable reports whether Syft would be able to index the
// target of the symlink at linkPath.
//
// It mirrors what the indexer does: resolve the link, then resolve the target's
// parent directory. A target that simply does not exist is fine — Syft skips a
// dangling link — so only permission-style failures quarantine the link.
func symlinkTargetResolvable(linkPath string) bool {
	target, err := os.Readlink(linkPath)
	if err != nil {
		// If we cannot even read the link, Syft will not get further either,
		// but there is no target to queue, so this is not the failure mode.
		return true
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(linkPath), target)
	}
	target = filepath.Clean(target)

	if _, err := os.Stat(target); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Dangling link: Syft's addSymlinkToIndex drops it. Harmless.
			return true
		}
		// Permission denied and friends: this is what kills the scan.
		return false
	}

	// The target exists, but indexTree additionally resolves its parent with
	// EvalSymlinks, which can still fail on a traversal-restricted directory.
	if _, err := filepath.EvalSymlinks(filepath.Dir(target)); err != nil {
		return false
	}
	return true
}

// absoluteMatchers converts root-relative exclusion patterns into the absolute
// form Syft matches against, so the preflight skips exactly the trees the scan
// will skip.
//
// Only "./"-anchored patterns are translated. "*/" and "**/" patterns are
// deliberately ignored here, which means the preflight still walks the paths
// they cover. That is the safe direction to be wrong in: the two glob forms do
// not mean quite the same thing once re-anchored ("*/" is one level, "**/" is
// any depth), and a matcher that skipped slightly too much would let exactly
// the symlink this whole pass exists to catch through, resurrecting the
// zero-component failure. Checking a few extra symlinks costs only lstat
// calls; missing one costs the entire scan.
func absoluteMatchers(absRoot string, excludes []string) []string {
	prefix := strings.TrimSuffix(absRoot, "/") + "/"
	out := make([]string, 0, len(excludes))
	for _, p := range excludes {
		if strings.HasPrefix(p, "./") {
			out = append(out, prefix+strings.TrimSuffix(strings.TrimPrefix(p, "./"), "/"))
		}
	}
	return out
}

// matchesAny reports whether path matches any of the doublestar patterns.
func matchesAny(patterns []string, p string) bool {
	for _, pattern := range patterns {
		if ok, err := doublestar.Match(pattern, p); err == nil && ok {
			return true
		}
	}
	return false
}

// relativeTo returns p relative to root in slash form.
func relativeTo(root, p string) (string, bool) {
	root = strings.TrimSuffix(root, "/")
	if root == "" {
		return strings.TrimPrefix(p, "/"), true
	}
	if !strings.HasPrefix(p, root+"/") {
		return "", false
	}
	return p[len(root)+1:], true
}

// escapeGlobMeta backslash-escapes the characters doublestar treats as pattern
// syntax, so a symlink whose name legitimately contains one of them still
// produces a pattern that matches exactly that file. A link called
// "libfoo[1].so" would otherwise become a character-class pattern that matches
// something else entirely, or nothing at all.
func escapeGlobMeta(p string) string {
	var b strings.Builder
	b.Grow(len(p) + 8)
	for _, r := range p {
		switch r {
		case '*', '?', '[', ']', '{', '}', '\\':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// truncateList returns at most n elements.
func truncateList(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}
