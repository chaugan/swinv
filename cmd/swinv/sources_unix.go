//go:build !windows

package main

// knownSourceProbes are the package databases worth checking for directly on a
// Unix host.
//
// Deliberately short. Each entry has to name a path whose absence genuinely
// means "this ecosystem is not installed here", or the manifest fills with
// skipped sources that mean nothing. The language ecosystems are excluded for
// that reason: there is no single file whose absence proves a host has no npm
// packages.
func knownSourceProbes() []sourceProbe {
	return []sourceProbe{
		{
			Name:  "dpkg",
			What:  "dpkg package database",
			Paths: []string{"var/lib/dpkg/status"},
		},
		{
			Name: "rpm",
			What: "rpm package database",
			// /usr/lib/sysimage/rpm first: on Fedora 36+ and openSUSE the
			// older path is a symlink to it, and on a scanned image the
			// symlink may not resolve inside the tree at all.
			Paths: []string{"usr/lib/sysimage/rpm", "var/lib/rpm"},
			Dir:   true,
		},
		{
			Name:  "apk",
			What:  "apk package database",
			Paths: []string{"lib/apk/db/installed"},
		},
		{
			Name:  "portage",
			What:  "portage package database",
			Paths: []string{"var/db/pkg"},
			Dir:   true,
		},
	}
}
