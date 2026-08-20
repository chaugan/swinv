//go:build windows

package sched

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func background() (notes, warnings []string) {
	// PROCESS_MODE_BACKGROUND_BEGIN is the single call Windows provides for
	// exactly this purpose. It lowers CPU priority *and* memory and I/O
	// priority for the process and every thread it owns, which is strictly
	// better than BELOW_NORMAL_PRIORITY_CLASS: that one leaves I/O at normal
	// priority, and I/O is what an inventory scan actually contends for.
	//
	// It only applies to the calling process, which is all swinv needs.
	err := windows.SetPriorityClass(windows.CurrentProcess(), windows.PROCESS_MODE_BACKGROUND_BEGIN)
	if err == nil {
		return []string{"process set to background mode (lowered CPU, I/O and memory priority)"}, nil
	}

	// The call fails if the process is already in background mode, which is
	// not a problem: the desired state is the current state.
	if err == windows.ERROR_PROCESS_MODE_ALREADY_BACKGROUND {
		return []string{"process was already in background mode"}, nil
	}

	// Fall back to lowering CPU priority alone rather than giving up entirely.
	if err2 := windows.SetPriorityClass(windows.CurrentProcess(), windows.BELOW_NORMAL_PRIORITY_CLASS); err2 == nil {
		return []string{"CPU priority lowered to below-normal"},
			[]string{fmt.Sprintf("could not enter background mode (%v); I/O priority is unchanged", err)}
	}
	return nil, []string{fmt.Sprintf("could not lower scheduling priority: %v", err)}
}
