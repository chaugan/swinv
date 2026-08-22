package scan

import (
	"path"
	"strings"

	"github.com/anchore/syft/syft/pkg"

	"github.com/chaugan/swinv/internal/model"
)

// resolveOwners answers, for a specific short list of paths, which package
// installed each one.
//
// It exists because a component's Locations are its *evidence* files, not its
// contents: a deb records /var/lib/dpkg/status and its own .list, never
// /usr/sbin/sshd. Joining a listening executable against Locations therefore
// finds nothing, and reports every daemon on a stock server as software no
// package manager installed -- which is the confident wrong answer the
// services section exists to avoid, in the direction that matters most.
//
// The package databases do carry the full file lists, and Syft has already
// parsed them into the package metadata. What they do not justify is building
// an index of all of it: a normal server's dpkg file lists run to hundreds of
// thousands of paths, and holding that map costs tens of megabytes to answer
// perhaps forty questions. So the caller supplies the paths it cares about
// first, and this checks membership instead of inverting the relation.
func resolveOwners(probe map[string]string, canon func(string) string, p pkg.Package, hits map[string][]int, index int) {
	if len(probe) == 0 {
		return
	}
	for _, f := range ownedFiles(p) {
		if f == "" {
			continue
		}
		if !strings.HasPrefix(f, "/") {
			f = "/" + f
		}
		if probed, ok := probe[canon(path.Clean(f))]; ok {
			hits[probed] = append(hits[probed], index)
		}
	}
}

// ownedFiles returns the paths a package's own database says it installed.
//
// Only the OS package managers are consulted. A language ecosystem's file list
// describes files inside its own installation tree, which cannot be a
// listening process's executable in any case that this is used for, and
// including them would trade a real answer for a plausible one.
func ownedFiles(p pkg.Package) []string {
	switch m := p.Metadata.(type) {
	case pkg.DpkgDBEntry:
		out := make([]string, 0, len(m.Files))
		for _, f := range m.Files {
			out = append(out, f.Path)
		}
		return out
	case pkg.RpmDBEntry:
		out := make([]string, 0, len(m.Files))
		for _, f := range m.Files {
			out = append(out, f.Path)
		}
		return out
	case pkg.ApkDBEntry:
		out := make([]string, 0, len(m.Files))
		for _, f := range m.Files {
			out = append(out, f.Path)
		}
		return out
	case pkg.AlpmDBEntry:
		out := make([]string, 0, len(m.Files))
		for _, f := range m.Files {
			out = append(out, f.Path)
		}
		return out
	}
	return nil
}

// finalizeOwners turns the recorded hits into the identity strings a consumer
// joins on.
//
// Components in a nested root are excluded. The path a hit matched is a path
// inside that nested tree, not on the host, so a snap base's openssh-server
// would otherwise be reported as the package behind the host's sshd -- the
// same class of mistake applyFileOwnership refuses for the same reason.
func finalizeOwners(components []model.Component, hits map[string][]int) map[string][]string {
	if len(hits) == 0 {
		return nil
	}
	out := make(map[string][]string, len(hits))
	for p, indices := range hits {
		var ids []string
		for _, i := range indices {
			if i >= len(components) || components[i].Root != hostRoot {
				continue
			}
			ids = append(ids, model.Identify(components[i]))
		}
		if len(ids) > 0 {
			out[p] = model.SortedSet(ids)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// probeSet normalises the caller's paths into the form the package databases
// spell them, so a caller passing "/usr/sbin/sshd/" or a relative path still
// gets an answer.
// probeSet normalises the caller's paths into the form the package databases
// are compared in, mapping each back to the path the caller asked about so the
// answer comes back under the name it will look the answer up by.
func probeSet(paths []string, canon func(string) string) map[string]string {
	if len(paths) == 0 {
		return nil
	}
	out := make(map[string]string, len(paths))
	for _, p := range paths {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		asked := p
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		out[canon(path.Clean(p))] = asked
	}
	return out
}
