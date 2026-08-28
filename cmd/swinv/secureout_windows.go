//go:build windows

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// secureOutputDir makes the output directory safe for a SYSTEM process to
// write root inventory into, on a host with unprivileged local users.
//
// The Windows problem POSIX modes do not cover: C:\ grants BUILTIN\Users
// "create folders", inherited into new subdirectories, so an unprivileged user
// can pre-create the --out path (default resolves to C:\var\lib\swinv) and
// become its owner with full control - then read everything SYSTEM writes
// there and overwrite what it transmits. os.Chmod only toggles the read-only
// bit and sets no DACL, so --perm 0600 is inert on Windows.
//
// If the directory is absent, it is created with an explicit DACL granting only
// SYSTEM and Administrators, not inherited from the parent. If it already
// exists, swinv refuses to run when the directory is owned by anyone other than
// SYSTEM, Administrators, or the account running the scan - the exact signal of
// an attacker having pre-seeded it - rather than silently trusting it.
func secureOutputDir(dir string) error {
	// D:PAI - protected DACL (no inherited ACEs), full access to Local System
	// (SY) and the Administrators group (BA), inheritable to child objects.
	const sddl = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		return refuseUnsafeOwner(dir)
	}

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("building the output directory ACL: %w", err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))

	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(p, &sa); err != nil {
		return fmt.Errorf("creating %s with an admin-only ACL: %w", dir, err)
	}
	return nil
}

// refuseUnsafeOwner returns an error if dir is owned by a principal that is not
// SYSTEM, the Administrators group, or the current process's user. An attacker
// who pre-created the directory is its CREATOR OWNER, which this catches.
func refuseUnsafeOwner(dir string) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("reading the owner of %s: %w", dir, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("reading the owner of %s: %w", dir, err)
	}
	if ownerIsTrusted(owner) {
		return nil
	}
	return fmt.Errorf("refusing to use %s: it is owned by %s, not SYSTEM, Administrators, "+
		"or this account. An unprivileged user could read or forge the inventory written "+
		"there; choose an admin-only directory (for example under %%ProgramData%%) or take "+
		"ownership and remove non-admin access", dir, owner.String())
}

// ownerIsTrusted reports whether sid is SYSTEM, the Administrators group, or
// the token user of the running process.
func ownerIsTrusted(sid *windows.SID) bool {
	for _, wk := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,
		windows.WinBuiltinAdministratorsSid,
	} {
		if known, err := windows.CreateWellKnownSid(wk); err == nil && sid.Equals(known) {
			return true
		}
	}
	if tok := windows.GetCurrentProcessToken(); tok != 0 {
		if u, err := tok.GetTokenUser(); err == nil && sid.Equals(u.User.Sid) {
			return true
		}
	}
	return false
}
