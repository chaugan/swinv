package scan

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/pkg"

	"github.com/chaugan/swinv/internal/model"
)

// expandProbeSymlinks lets a probed path that is a symlink also answer for
// the file it resolves to.
//
// The package databases and the filesystem disagree about symlinked entry
// points: dpkg's md5sums - the list Syft parses - can only name files with
// contents, so /usr/bin/rm as a symlink to a multi-call binary appears in
// .list but never in the metadata this join runs against. Ubuntu's coreutils
// transition makes that the normal shape of /usr/bin, not a curiosity: every
// unit file spelling /bin/rm would report an unowned executable on a host
// where the owner is one readlink away. The chase is jailed under the scan
// root - an absolute symlink inside an image must resolve inside that image,
// never onto the scanning host - and bounded, because a symlink loop must
// cost eight hops, not a scan.
func expandProbeSymlinks(probe map[string][]string, root string, canon func(string) string) {
	keys := make([]string, 0, len(probe))
	for k := range probe {
		keys = append(keys, k)
	}
	for _, key := range keys {
		resolved := chaseSymlink(root, key)
		if resolved == "" || resolved == key {
			continue
		}
		ck := canon(resolved)
		if ck == key {
			continue
		}
		probe[ck] = append(probe[ck], probe[key]...)
	}
}

func chaseSymlink(root, p string) string {
	const maxHops = 8
	for hop := 0; hop < maxHops; hop++ {
		full := filepath.Join(root, filepath.FromSlash(p))
		fi, err := os.Lstat(full)
		if err != nil {
			return ""
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			if fi.Mode().IsRegular() {
				return p
			}
			return ""
		}
		target, err := os.Readlink(full)
		if err != nil {
			return ""
		}
		if strings.HasPrefix(target, "/") {
			p = path.Clean(target)
		} else {
			p = path.Join(path.Dir(p), target)
		}
	}
	return ""
}

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
func resolveOwners(probe map[string][]string, canon func(string) string, p pkg.Package, hits map[string][]int, index int) {
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
		for _, probed := range probe[canon(path.Clean(f))] {
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
// are compared in, mapping each back to every path it was asked about so the
// answers come back under the names the callers will look them up by.
//
// Every, not the last: /bin/mount from a systemd unit and /usr/bin/mount from
// the SUID walk are the same file after the /usr merge, and when the map held
// a single asked path the second asker silently evicted the first - mount
// reported as an unowned SUID binary on a host where the mount package
// plainly owns it, purely because a snapd unit spelled the same file the
// pre-merge way.
func probeSet(paths []string, canon func(string) string) map[string][]string {
	if len(paths) == 0 {
		return nil
	}
	out := make(map[string][]string, len(paths))
	for _, p := range paths {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		asked := p
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		key := canon(path.Clean(p))
		out[key] = append(out[key], asked)
	}
	return out
}
