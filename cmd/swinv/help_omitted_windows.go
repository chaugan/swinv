//go:build windows

package main

// helpOmittedFlags are registered but deliberately absent from the Windows
// help page: they describe a Linux filesystem layout, and the Windows
// collector does not walk one by default.
func helpOmittedFlags() []string {
	return []string{
		"root", "include-home", "no-snap", "no-flatpak",
		"no-auto-exclude-mounts", "skip-nested-rootfs", "require-host-id",
		// ELF is a Linux object format; the PE import table would be its
		// Windows sibling and is not built yet.
		"elf-scope", "elf-symbols",
	}
}
