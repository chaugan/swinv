//go:build !windows

package main

import (
	"fmt"
	"os"
)

// refuseOpenPassphraseFile refuses a passphrase file another user can read.
// An encrypted key whose passphrase is group- or world-readable protects
// nothing, and the refusal here is cheaper than the audit finding later.
// Same style of refusal as --perm: state the fix, not just the fact.
func refuseOpenPassphraseFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("--transmit-key-passphrase-file: %w", err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("--transmit-key-passphrase-file: %s is mode %04o and readable by others; "+
			"chmod 600 it, or use a systemd credential", path, mode)
	}
	return nil
}
