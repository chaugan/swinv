package appx

import "errors"

// ErrUnsupportedPlatform is returned on anything other than Windows.
var ErrUnsupportedPlatform = errors.New("appx: Appx packages and the component store exist only on Windows")

// Update is one installed servicing package.
//
// Deliberately not a flat KB number. Windows quality updates are cumulative:
// each replaces its predecessor and the store records the current one under an
// identity carrying no KB at all, so "is KB5121003 installed?" false-negatives
// a fully patched machine a month later. Measured on one laptop, the component
// store and Win32_QuickFixEngineering each held two KBs the other lacked --
// not because either was broken, but because they name different things.
type Update struct {
	// Kind is which servicing stream this belongs to.
	Kind Kind

	// KB is set only where a KB number really is the identity: out-of-band
	// fixes and enablement packages. Empty for cumulative and servicing-stack
	// updates, which Windows identifies by version.
	KB string

	// Version is the package version. For a cumulative update it is the
	// build and UBR, the same value as the host's kernel_release, which is
	// what makes it comparable against a patch-level baseline.
	Version string

	// Identity is the full component-store package name, kept because it is
	// the only unambiguous handle on a specific package.
	Identity string

	// Pending is true when the package is installed but not yet live, which
	// means the running system is still on the previous patch level.
	Pending bool

	// Components is how many component-store packages carry this update.
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

// ReadUpdates returns the servicing packages the component store records as
// installed.
//
// Not Win32_QuickFixEngineering, and not because that class is wrong -- it
// answers a different question. WMI reports current hotfixes, mapped to their
// KB numbers; the component store reports packages, by identity and state.
// Reading the store means superseded packages must be filtered by CurrentState,
// which is the fix for reporting .NET rollups a machine replaced months ago.
func ReadUpdates() ([]Update, error) { return readUpdates() }
