//go:build linux

package service

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// readProcess gathers what /proc says about a process.
//
// Every field is optional. A process can exit between being listed and being
// read, and an unprivileged scan cannot read another user's exe link at all,
// so each value is taken if available and skipped if not. What survives is
// still worth having: the cgroup is world-readable, so the owning unit is
// usually known even when the executable is not.
func readProcess(procRoot string, pid int) Process {
	dir := filepath.Join(procRoot, fmt.Sprint(pid))
	p := Process{PID: pid}

	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		p.Exe = exe
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		// argv is NUL-separated, with a trailing NUL.
		p.Command = strings.TrimSpace(string(bytes.ReplaceAll(bytes.TrimRight(raw, "\x00"), []byte{0}, []byte{' '})))
	}
	if f, err := os.Open(filepath.Join(dir, "cgroup")); err == nil {
		p.Unit, p.Container = UnitFromCgroup(f)
		_ = f.Close()
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		p.User = uidFromStatus(raw)
	}
	p.Isolated = isolatedFrom(procRoot, dir, p.Exe)
	return p
}

// isolatedFrom reports whether the process is in a different mount namespace
// than init, and therefore whether its Exe path describes this host.
//
// An unreadable link is reported as not isolated. Reading another process's
// namespace links needs root, and an unprivileged scan cannot attribute
// sockets to other users' processes in the first place -- so the only
// processes reaching this without an answer are the scan's own, which are on
// the host by definition. Defaulting the other way would drop the attribution
// for every service on an unprivileged run that did resolve.
func isolatedFrom(procRoot, dir, exe string) bool {
	self, err := os.Readlink(filepath.Join(dir, "ns", "mnt"))
	if err != nil || self == "" {
		return false
	}
	init, err := os.Readlink(filepath.Join(procRoot, "1", "ns", "mnt"))
	if err != nil || init == "" {
		return false
	}
	if self == init {
		return false
	}

	// A different mount namespace is not, by itself, a different filesystem.
	// systemd's sandboxing (ProtectSystem, PrivateTmp) gives a unit its own
	// namespace over the same root -- on an Ubuntu 24.04 host that is
	// systemd-resolved, networkd and chronyd, and treating them as isolated
	// reported every core daemon on the machine as software nothing installed.
	// So the executable itself is the tiebreak: if the path names the same
	// file (device and inode) through the process's root as through the
	// host's, joining it to host packages is joining the file that is
	// actually running. A container's same-named path is a different inode
	// and stays isolated, which is the case the guard exists for.
	if exe != "" {
		inProcess, err1 := os.Stat(filepath.Join(dir, "root", filepath.FromSlash(exe)))
		onHost, err2 := os.Stat(filepath.FromSlash(exe))
		if err1 == nil && err2 == nil && os.SameFile(inProcess, onHost) {
			return false
		}
	}
	return true
}

// uidFromStatus reads the real uid from /proc/<pid>/status, whose Uid line is
// "Uid:\treal\teffective\tsaved\tfs".
func uidFromStatus(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		if fields := strings.Fields(line); len(fields) > 1 {
			return fields[1]
		}
	}
	return ""
}
