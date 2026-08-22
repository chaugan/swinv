package ctrpkg

import (
	"os"
	"path"
	"path/filepath"
	"strconv"

	rpmdb "github.com/anchore/go-rpmdb/pkg"
)

// rpmDBPaths are where the RPM database lives, newest layout first. RHEL 9 and
// Fedora moved it to /usr/lib/sysimage/rpm; RHEL 8 and earlier keep it in
// /var/lib/rpm, and both may be a symlink to the other.
var rpmDBPaths = []string{
	"usr/lib/sysimage/rpm",
	"var/lib/rpm",
}

// rpmDBFiles are the database files, by backend: sqlite on RHEL 9+, ndb on
// SUSE, Berkeley DB on RHEL 8 and earlier. go-rpmdb sniffs which it was given,
// so the only job here is to find a file to hand it.
var rpmDBFiles = []string{"rpmdb.sqlite", "Packages.db", "Packages"}

// probeRPM answers from the container's RPM database.
//
// The database is opened read-only and only the packages that own a probed
// path are kept. Listing every package would be the same mistake the host join
// avoids: a full RHEL container holds several hundred, and the question asked
// was about the four executables that are listening.
func probeRPM(root string, want map[string]string, canon func(string) string, rel Release, out map[string]Owner) {
	dbPath := findRPMDB(root)
	if dbPath == "" {
		return
	}

	db, err := rpmdb.Open(dbPath)
	if err != nil || db == nil {
		return
	}
	defer func() { _ = db.Close() }()

	packages, err := db.ListPackages()
	if err != nil {
		return
	}

	for _, p := range packages {
		if p == nil {
			continue
		}
		files, err := p.InstalledFileNames()
		if err != nil {
			continue
		}
		for _, f := range files {
			asked, ok := want[canon(path.Clean(f))]
			if !ok {
				continue
			}
			if _, taken := out[asked]; taken {
				continue
			}
			version := rpmVersion(p.Epoch, p.Version, p.Release)
			out[asked] = Owner{
				Name: p.Name, Version: version, Arch: p.Arch, Type: "rpm",
				PURL: purl("rpm", rel, p.Name, version, p.Arch),
			}
		}
	}
}

// findRPMDB locates a readable RPM database under root.
func findRPMDB(root string) string {
	for _, dir := range rpmDBPaths {
		for _, name := range rpmDBFiles {
			candidate := filepath.Join(root, dir, name)
			// #nosec G703 -- dir and name come from the constant lists above,
			// so no part of this path is chosen by the container.
			if fi, err := os.Stat(candidate); err == nil && fi.Mode().IsRegular() {
				return candidate
			}
		}
	}
	return ""
}

// rpmVersion renders the version the way RPM consumers spell it, with the
// epoch only when there is one. Emitting "0:" where RPM itself would print
// nothing produces a string that fails to match every advisory.
func rpmVersion(epoch *int, version, release string) string {
	out := version
	if release != "" {
		out += "-" + release
	}
	if epoch != nil && *epoch != 0 {
		out = strconv.Itoa(*epoch) + ":" + out
	}
	return out
}
