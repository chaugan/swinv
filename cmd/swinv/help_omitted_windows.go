//go:build windows

package main

// helpOmittedFlags are registered but deliberately absent from the Windows
// help page: they describe a Linux filesystem layout, and the Windows
// collector does not walk one by default.
//
// --no-services and --no-service-command are here for a different reason:
// service detection is built on /proc, so on Windows there is nothing for
// either flag to turn off. They stay registered so a runbook written for the
// Linux fleet does not fail to parse on a Windows box.
func helpOmittedFlags() []string {
	return []string{
		"root", "include-home", "no-snap", "no-flatpak",
		"no-auto-exclude-mounts", "skip-nested-rootfs", "require-host-id",
		"no-services", "no-service-command",
	}
}
