//go:build unix

package main

import (
	"os"
	"syscall"
)

// writeExclusive creates path with O_EXCL|O_NOFOLLOW at mode 0600, refusing an
// existing file or a symlink - so the root process cannot be tricked into
// overwriting an attacker-chosen target or writing the dump through a planted
// link.
func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(data)
	return err
}
