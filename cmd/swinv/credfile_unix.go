//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// openCredential opens a secret file (token, key, passphrase) safely for a
// root process on a shared host: O_NOFOLLOW so a symlink an unprivileged user
// planted cannot redirect the read, then fstat on the descriptor (not a
// separate Stat that races the read) to verify the file is owned by this
// process's user (root) and readable by nobody else. It returns the open file;
// the caller reads and closes it. This closes the symlink-follow, the
// ownership gap, and the stat/read TOCTOU together.
func openCredential(path, what string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (a symlink is refused; provide a real file)", what, err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if ok {
		euid := os.Geteuid()
		if euid >= 0 && st.Uid != uint32(euid) && st.Uid != 0 { // #nosec G115 -- a uid is non-negative and fits uint32
			_ = f.Close()
			return nil, fmt.Errorf("%s: %s is owned by uid %d, not this process; refusing to read a "+
				"credential another user controls", what, path, st.Uid)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			_ = f.Close()
			return nil, fmt.Errorf("%s: %s is mode %04o and readable by others; chmod 600 it",
				what, path, fi.Mode().Perm())
		}
	}
	return f, nil
}
