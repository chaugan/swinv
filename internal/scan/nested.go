package scan

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// packageDBDirs are the directories a Linux package manager keeps its
// installed-package database in. Matching on the *directory* rather than on a
// specific filename is deliberate: the databases underneath have many names
// and keep gaining more - dpkg has status and status.d/*, rpm has Packages,
// Packages.db and rpmdb.sqlite, pacman has local/<pkg>/desc, portage has
// <category>/<pkg>/CONTENTS. Anchoring on the directory catches all of them,
// and any future sibling, without a filename list that silently goes stale.
//
// Every entry begins and ends with "/" so it can only match whole path
// segments: "/var/lib/rpm/" cannot match "/srv/myvar/lib/rpmthing".
var packageDBDirs = []string{
	"/var/lib/dpkg/",
	"/var/lib/rpm/",
	"/usr/lib/sysimage/rpm/",
	"/usr/share/rpm/",
	"/lib/apk/db/",
	"/var/lib/pacman/local/",
	"/var/db/pkg/",
	// A base snap keeps its package list here rather than in a dpkg database.
	// Without this entry a base snap is not recognised as a nested root at
	// all, so every file in it is attributed to the host -- and a base snap is
	// a different operating system: core18 is Ubuntu 18.04, core20 is 20.04,
	// each with its own release, its own package set, and its own update
	// cadence through snap refresh rather than apt.
	"/usr/share/snappy/",
}

// maxListedNestedRoots caps how many nested roots a single warning names.
const maxListedNestedRoots = 5

// DetectNestedRoots reports package databases discovered inside a second root
// filesystem rather than the one being scanned.
//
// This exists because of a genuinely confusing failure mode. An extracted
// tarball, a container rootfs backup, a chroot, or a test fixture sitting on
// disk all contain their own package database, and a scan of "/" walks into it
// and reports its contents as installed software. Worse, those components are
// labelled with the *host's* distribution, because distro detection happens
// once for the whole scan - so a Debian 12 package from an extracted image
// appears in an Ubuntu host's inventory as though it were installed, with
// nothing to mark it as foreign.
//
// swinv deliberately does not exclude these automatically. Scanning a chroot or
// a mounted image is a legitimate thing to want, and silently dropping it would
// be its own surprise. Instead the operator is told what was found and where,
// so they can add an --exclude if it is not what they meant.
//
// Only meaningful when scanning the real root: any other --root is itself a
// tree whose layout swinv cannot assume, so no warning is produced.
func DetectNestedRoots(root string, components []model.Component) []string {
	roots := NestedRoots(root, components)
	if len(roots) == 0 {
		return nil
	}

	shown := roots
	if len(shown) > maxListedNestedRoots {
		shown = shown[:maxListedNestedRoots]
	}
	return []string{fmt.Sprintf(
		"found %d nested root filesystem(s) containing their own package databases: %s. "+
			"Their packages are reported as installed and carry this host's distribution label, "+
			"which is usually not what you want. Pass --skip-nested-rootfs to leave them "+
			"out, or --exclude './path/**' to skip the tree entirely",
		len(roots), summarizeList(shown))}
}

// NestedRoots returns the directories holding a package database that is not
// the scanned root's own, sorted. Empty for any --root other than "/", because
// an arbitrary tree is itself a nested root and warning about it is noise.
func NestedRoots(root string, components []model.Component) []string {
	if normalizeRoot(root) != "/" {
		return nil
	}
	found := make(map[string]struct{})
	for _, c := range components {
		for _, loc := range c.Locations {
			if prefix, ok := nestedRootPrefix(loc); ok {
				found[prefix] = struct{}{}
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	out := make([]string, 0, len(found))
	for r := range found {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// DropNestedRootComponents removes components whose package-database evidence
// comes only from nested root filesystems.
//
// Two rules matter here, and both were learned the hard way:
//
// A component is judged on its *database* evidence, not on its paths in
// general. Syft's file-ownership overlap routinely attaches a real host path
// such as /usr/share/doc/libssl3t64/copyright to a package it read from a
// nested dpkg status file, so "every location is inside the nested tree" is
// too weak a rule and leaves the phantoms in place.
//
// A component is kept if it *also* cites the scanned root's own database. Syft
// can merge a genuinely installed package with a same-name entry from a nested
// tree, and dropping that would lose real installed software - far worse than
// reporting one package too many.
func DropNestedRootComponents(components []model.Component, roots []string) (kept []model.Component, dropped int) {
	if len(roots) == 0 {
		return components, 0
	}
	kept = make([]model.Component, 0, len(components))
	for _, c := range components {
		if onlyNestedDatabaseEvidence(c) {
			dropped++
			continue
		}
		kept = append(kept, c)
	}
	return kept, dropped
}

// onlyNestedDatabaseEvidence reports whether a component cites at least one
// nested package database and none belonging to the scanned root.
func onlyNestedDatabaseEvidence(c model.Component) bool {
	var nested, host bool
	for _, loc := range c.Locations {
		if _, isNested := nestedRootPrefix(loc); isNested {
			nested = true
		} else if isHostPackageDBPath(loc) {
			host = true
		}
	}
	return nested && !host
}

// isHostPackageDBPath reports whether a path is a package database belonging to
// the root being scanned rather than a nested one.
func isHostPackageDBPath(loc string) bool {
	probe := path.Clean(loc) + "/"
	for _, dir := range packageDBDirs {
		if strings.HasPrefix(probe, dir) {
			return true
		}
	}
	return false
}

// nestedRootPrefix reports the directory a package database sits under when
// that database belongs to a nested root filesystem rather than the scanned
// one. The returned prefix is the nested root itself.
func nestedRootPrefix(loc string) (string, bool) {
	// The trailing "/" is appended so a location that IS the database
	// directory ("/image/var/lib/rpm") matches as readily as a file inside it
	// ("/image/var/lib/rpm/Packages"). Syft reports both forms depending on
	// the cataloger.
	probe := path.Clean(loc) + "/"
	for _, dir := range packageDBDirs {
		idx := strings.Index(probe, dir)
		if idx < 0 {
			continue
		}
		if idx == 0 {
			// The scanned root's own database.
			return "", false
		}
		return probe[:idx], true
	}
	return "", false
}
