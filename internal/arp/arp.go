// Package arp reads Windows installed-software entries from the registry --
// the Add/Remove Programs, or "uninstall", keys.
//
// This is the Windows equivalent of a package database, and like a package
// database it is metadata: names, versions, publishers and install locations,
// read without opening a single file. On Linux swinv gets a near-complete
// inventory from /var/lib/dpkg/status or rpmdb.sqlite in about a second. This
// is the same move on Windows, and it is why the registry rather than the
// filesystem is the source of truth here.
//
// Explicitly NOT via Win32_Product. Enumerating that WMI class triggers an MSI
// consistency check against every installed product, which can reconfigure or
// repair software -- unacceptable for a tool whose job is to observe. It also
// only sees MSI installs. See docs/WINDOWS.md.
package arp

import "errors"

// ErrUnsupportedPlatform is returned on anything other than Windows.
var ErrUnsupportedPlatform = errors.New("arp: the uninstall registry only exists on Windows")

// Scope records which hive an entry came from, because the answer changes what
// the entry means: a machine-wide install affects everyone, a per-user one does
// not, and the same product can appear in both.
type Scope string

const (
	// ScopeMachine is HKLM\Software\...\Uninstall -- native-bitness installs.
	ScopeMachine Scope = "machine"
	// ScopeMachine32 is HKLM\Software\WOW6432Node\...\Uninstall -- 32-bit
	// installs on a 64-bit system, which live in a separate key entirely and
	// are invisible to code that reads only the native one.
	ScopeMachine32 Scope = "machine-x86"
	// ScopeUser is HKCU\Software\...\Uninstall, for the invoking user only.
	// Other users' hives are not loaded and are not read.
	ScopeUser Scope = "user"
)

// Entry is one row of Add/Remove Programs.
type Entry struct {
	// Key is the registry key name, which for MSI installs is the product
	// code GUID and is the most stable identity available.
	Key   string
	Scope Scope

	DisplayName     string
	DisplayVersion  string
	Publisher       string
	InstallLocation string
	InstallDate     string

	// SystemComponent is set on entries hidden from the Add/Remove Programs
	// UI. They are real software -- runtimes, redistributables, driver
	// packages -- but including them makes a Windows count look inflated next
	// to what an operator sees, so the decision is left to the caller.
	SystemComponent bool

	// WindowsInstaller marks an MSI-installed product, whose Key is its
	// product code.
	WindowsInstaller bool
}

// Read returns every uninstall entry visible to this process, across all three
// scopes.
//
// Entries with no DisplayName are skipped: they are placeholders and orphaned
// keys, not software. Nothing else is filtered, because which entries count as
// "installed software" is a policy question and belongs to the caller.
func Read() ([]Entry, error) { return read() }
