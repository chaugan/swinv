//go:build !linux && !windows

package sched

// background is a no-op on platforms swinv does not ship for. Reporting a
// warning here would be noise: nobody is running this configuration.
func background() (notes, warnings []string) { return nil, nil }
