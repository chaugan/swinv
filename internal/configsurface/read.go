package configsurface

import (
	"io"
	"os"
)

// maxConfigFile bounds any single configuration file this package reads. Real
// crontabs, unit files, sudoers and authorized_keys are kilobytes; 8 MiB is
// generous for anything legitimate and small enough that a pathological file
// degrades one inventory row instead of the host. The collector runs as root,
// and some of the files it reads live in directories an unprivileged user
// owns (a home directory's authorized_keys), so an unbounded os.ReadFile is a
// denial-of-service the attacker can aim at the root process.
const maxConfigFile = 8 << 20

// readCapped reads a file only if it is a regular file, and never more than
// maxConfigFile bytes.
//
// The regular-file gate is the important half: a symlink to /dev/zero would
// otherwise stream forever, a FIFO would block the read syscall past any
// context deadline, and a device or socket has no business here. os.Lstat -
// not Stat - so a symlink is judged as a symlink, and the read that follows
// opens the path (following the link to its target) only after the target has
// been confirmed regular by the caller where ownership matters.
func readCapped(path string) ([]byte, bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, false
	}
	// A symlink is resolved and re-checked below; a non-regular non-symlink
	// (device, FIFO, socket, directory) is refused outright.
	if fi.Mode()&os.ModeSymlink == 0 && !fi.Mode().IsRegular() {
		return nil, false
	}
	// O_NONBLOCK so a symlink to a FIFO does not block the root process inside
	// open(2) - open(fifo, O_RDONLY) without it waits for a writer that may
	// never come. It is a no-op for the regular files this reads. The Lstat
	// above only saw the link; the fstat below judges the file actually
	// opened, so a symlink to /dev/zero, a FIFO, or a device is refused here.
	f, err := openNonBlocking(path) // #nosec G304 -- path under the scan root; type checked on the opened fd below
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigFile))
	if err != nil {
		return nil, false
	}
	return data, true
}

// readOwnedByCapped is readCapped plus an ownership gate: the opened file must
// be owned by wantUID or by root. It exists for files that live in a
// directory an unprivileged user controls - a home directory's
// authorized_keys - where a symlink to a root-only file (/root/.aws/
// credentials) would otherwise be read by the root process and its contents
// serialized into a report the attacker can read back. A legitimate key file
// is owned by its own account; a symlink to another user's or root's file
// resolves to a differently-owned file and is refused.
func readOwnedByCapped(path string, wantUID uint32) ([]byte, bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, false
	}
	wasSymlink := fi.Mode()&os.ModeSymlink != 0
	if !wasSymlink && !fi.Mode().IsRegular() {
		return nil, false
	}
	f, err := openNonBlocking(path) // #nosec G304 -- path under the scan root; ownership, type and size enforced on the opened fd below
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	uid, haveUID := fileUID(st)
	if haveUID {
		// A file reached through a symlink must resolve to the account's own
		// file. Allowing root-owned (uid 0) here as well - which a hardened
		// sshd's StrictModes does permit for a real authorized_keys - would
		// also admit a symlink an unprivileged user planted at
		// ~/.ssh/authorized_keys pointing at /root/.aws/credentials, turning
		// the root collector into an exfiltration oracle for root-only files.
		// So root ownership is accepted only for a genuine (non-symlinked)
		// file; a symlink must be owned by the account itself.
		if wasSymlink {
			if uid != wantUID {
				return nil, false
			}
		} else if uid != wantUID && uid != 0 {
			return nil, false
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigFile))
	if err != nil {
		return nil, false
	}
	return data, true
}
