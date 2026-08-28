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
	f, err := os.Open(path) // #nosec G304 -- caller passes a path under the scan root; size and type are bounded here
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	// After opening (which follows a symlink), confirm the thing actually
	// opened is a regular file, so a symlink to /dev/zero or a FIFO is caught
	// even though Lstat saw only the link.
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
	if fi.Mode()&os.ModeSymlink == 0 && !fi.Mode().IsRegular() {
		return nil, false
	}
	f, err := os.Open(path) // #nosec G304 -- path under the scan root; ownership and size are enforced below
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	if uid, ok := fileUID(st); ok && uid != wantUID && uid != 0 {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigFile))
	if err != nil {
		return nil, false
	}
	return data, true
}
