//go:build windows

package privilege

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func check() Status {
	// The elevation flag lives on the process token, which is the only place
	// Windows records it. Membership of the Administrators group is not the
	// same question: under UAC a member runs with a filtered token and cannot
	// read what an elevated one can.
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return Status{
			Warning: fmt.Sprintf(
				"could not determine whether this process is elevated (%v): "+
					"the inventory may be incomplete without swinv being able to say so", err),
		}
	}
	defer token.Close()

	if token.IsElevated() {
		return Status{Elevated: true, Known: true}
	}
	return Status{
		Known: true,
		Warning: "not running elevated: directories protected by ACLs were skipped, " +
			"so the inventory may be incomplete",
	}
}
