//go:build !unix

package main

import "os"

// writeExclusive creates path with O_EXCL at mode 0600 (no O_NOFOLLOW: not a
// portable flag off unix). O_EXCL still refuses an existing file, which is the
// larger half of the guard.
func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(data)
	return err
}
