//go:build !windows

package scan

// defaultMountinfoPath is the kernel's per-process mount table. It is the
// authoritative list of what is mounted where, including the filesystem type,
// which is what lets swinv skip network and virtual filesystems.
const defaultMountinfoPath = "/proc/self/mountinfo"

// noMountTableWarning is unused here: this platform has a mount table.
const noMountTableWarning = ""
