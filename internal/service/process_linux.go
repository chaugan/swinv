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
	return p
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
