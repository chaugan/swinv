package appx

import "errors"

// ErrUnsupportedPlatform is returned on anything other than Windows.
var ErrUnsupportedPlatform = errors.New("appx: Appx packages and the component store exist only on Windows")

// Update is one Windows update, identified by its knowledge-base number.
type Update struct {
	// KB is the number an operator patches by, e.g. "KB5062553".
	KB string

	// Components is how many component-store packages carry this KB. Recorded
	// because it is the only evidence of scale available here, and because a
	// count of one is worth treating differently from a count of nine hundred.
	Components int
}

// ReadPackages returns the Appx and MSIX packages installed for the user
// running the scan.
//
// Per-user by construction. Store apps are installed per user, and the
// registry this reads is HKCU, so a scan running as a service account sees
// that account's packages and no one else's -- the same blind spot the
// uninstall registry has, for the same reason.
func ReadPackages() ([]Package, error) { return readPackages() }

// ReadUpdates returns the Windows updates the component store records.
//
// Deliberately not Win32_QuickFixEngineering, which is what Get-HotFix uses:
// on a machine whose component store held 7,844 package entries, that class
// reported three updates. It has not been a complete record of Windows
// servicing for years.
func ReadUpdates() ([]Update, error) { return readUpdates() }
