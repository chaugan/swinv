//go:build !windows

package privilege

import "os"

func check() Status {
	if os.Geteuid() == 0 {
		return Status{Elevated: true, Known: true}
	}
	return Status{
		Known:   true,
		Warning: "not running as root: root-only paths and DMI identifiers were skipped",
	}
}
