//go:build windows

package main

// refuseOpenPassphraseFile is a no-op on Windows: POSIX mode bits are a
// fiction here, and pretending to check them would be theatre of the exact
// kind the check exists to prevent. ACLs are the real control and are the
// operator's to set.
func refuseOpenPassphraseFile(string) error { return nil }
