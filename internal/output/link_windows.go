//go:build windows

package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// createLink makes tmp point at target, degrading through three mechanisms.
//
// Creating a symbolic link on Windows requires SeCreateSymbolicLinkPrivilege,
// which an ordinary account does not hold unless Developer Mode is on. So the
// obvious implementation fails on every unelevated run with "A required
// privilege is not held by the client" -- twice per run, once per format --
// which is what a real Windows tester saw.
//
// The fallbacks need no privilege:
//
//   - A hard link is exact. It costs nothing, and because the link is recreated
//     on every run it always names the current report. Its one difference from
//     a symlink is that deleting the dated file leaves the content reachable
//     through the link rather than leaving a dangling one, which for a
//     "latest" pointer is harmless.
//   - A copy works anywhere, including across volumes, at the cost of a second
//     copy of a file that is usually well under a megabyte.
//
// Falling back silently is deliberate. The operator asked for a latest pointer,
// they have one, and the mechanism is an implementation detail -- warning about
// it on every run would train them to ignore warnings.
func createLink(target, tmp, dir string) error {
	if err := os.Symlink(target, tmp); err == nil {
		return nil
	}

	// UpdateSymlink stores a bare basename when the target is in the same
	// directory, which a symlink resolves relative to its own location. A hard
	// link and a copy both need a real path.
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(dir, resolved)
	}

	if err := os.Link(resolved, tmp); err == nil {
		return nil
	}
	return copyFile(resolved, tmp)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening %s: %w", src, err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("creating %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("copying %s to %s: %w", src, dst, err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("syncing %s: %w", dst, err)
	}
	return out.Close()
}
