package output

import "syscall"

// syscallUmask sets the process umask and returns the previous value. It lives
// in its own file so the one Unix-only call in the tests is easy to find.
func syscallUmask(mask int) int { return syscall.Umask(mask) }
