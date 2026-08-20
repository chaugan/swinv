//go:build linux

package sched

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// niceValue is how far the scan steps back from interactive work. 10 is the
// conventional value for batch and maintenance jobs -- enough that anything a
// person is waiting on preempts the scan, not so much that the scan starves
// outright on a busy machine, which 19 risks.
const niceValue = 10

// Linux I/O priority, from include/uapi/linux/ioprio.h. IOPRIO_CLASS_IDLE only
// gets disk time when nothing else wants it, which is exactly the behaviour a
// background inventory should have. Unlike the realtime class it needs no
// privileges, so this works for an unprivileged run too.
const (
	ioprioWhoProcess  = 1
	ioprioClassIdle   = 3
	ioprioClassShift  = 13
	ioprioIdleForSelf = ioprioClassIdle << ioprioClassShift
)

func background() (notes, warnings []string) {
	// Lowering priority never requires privilege; raising it does. If the
	// caller has already been niced further down than this, the call fails and
	// that is correct -- swinv should not undo an operator's stricter setting.
	if err := unix.Setpriority(unix.PRIO_PROCESS, 0, niceValue); err != nil {
		warnings = append(warnings, fmt.Sprintf(
			"could not lower CPU scheduling priority to nice %d: %v", niceValue, err))
	} else {
		notes = append(notes, fmt.Sprintf("CPU priority set to nice %d", niceValue))
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET,
		ioprioWhoProcess, 0, ioprioIdleForSelf); errno != 0 {
		warnings = append(warnings, fmt.Sprintf(
			"could not lower I/O scheduling priority to the idle class: %v", errno))
	} else {
		// Worth knowing that this can be applied successfully and still do
		// nothing: only BFQ honours I/O priority classes. The schedulers most
		// distributions now default to for NVMe, mq-deadline and none, ignore
		// them, and there is no way to ask the kernel whether the call will
		// have an effect. The nice value above still helps in that case.
		notes = append(notes, "I/O priority set to the idle class (honoured only by the BFQ scheduler)")
	}
	return notes, warnings
}
