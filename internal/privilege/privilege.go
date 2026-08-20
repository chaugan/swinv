// Package privilege reports whether the process holds enough privilege to read
// everything a complete inventory needs.
//
// It exists because the obvious check is wrong on one of the two platforms
// swinv builds for. os.Geteuid returns a hard-coded -1 on Windows -- not an
// error, not an unsupported marker, just -1 -- so `os.Geteuid() == 0` reports
// "unprivileged" for a fully elevated Administrator. That is worse than not
// knowing: it puts a confident false value in the report's ran_as_root field,
// where a consumer has no way to tell it apart from a genuinely unprivileged
// run.
package privilege

// Status describes the process's privilege level and how to describe it to an
// operator.
type Status struct {
	// Elevated is true when the process can read the whole filesystem:
	// uid 0 on Unix, an elevated token on Windows.
	Elevated bool

	// Known is false when the platform could not answer. Callers should treat
	// an unknown result as unprivileged for the purpose of trusting the
	// inventory, but must not claim it was unprivileged.
	Known bool

	// Warning is what to tell the operator, empty when there is nothing worth
	// saying. It is phrased for the platform: "root" means nothing on Windows
	// and "Administrator" means nothing on Linux.
	Warning string
}

// Check reports the current process's privilege level.
func Check() Status { return check() }
