//go:build !windows

package output

import "os"

// createLink makes tmp a symlink to target. Unix places no privilege
// requirement on that, so there is nothing to fall back to.
//
// dir is unused here; the Windows implementation needs it to resolve a
// relative target for its fallbacks.
func createLink(target, tmp, _ string) error { return os.Symlink(target, tmp) }
