//go:build windows

package scan

// Windows exposes no equivalent of /proc/self/mountinfo. The comparable
// information comes from enumerating volumes and asking GetDriveType for each,
// which swinv does not do yet -- see docs/WINDOWS.md.
const defaultMountinfoPath = ""

// noMountTableWarning states the consequence rather than the missing file. The
// consequence is what an operator can act on: without drive-type filtering, a
// mapped network drive or a cloud-sync folder underneath the scan root is
// walked like any local directory.
const noMountTableWarning = "no mount table is available on this platform, so network drives, " +
	"removable media and cloud-sync folders under the scan root are not excluded " +
	"automatically; pass --exclude for any that should be skipped"
