// Package ctrpkg identifies the package that installed a given executable
// inside a container, by reading that container's own package database
// through /proc/<pid>/root.
//
// This exists because the alternatives are both wrong. Naming the image --
// pkg:oci/splunk@sha256:... -- produces an identifier no vulnerability matcher
// can use: Grype has no oci matcher, OSV and OSS Index have no OCI
// coordinates, and Dependency-Track ingests it, finds nothing, and shows the
// component as clean, which is indistinguishable from "analysed and safe".
// Cataloguing the whole container filesystem produces a real answer at a cost
// that is not proportionate: a full walk of one container rootfs on the
// development host ran past ten minutes without finishing.
//
// So the same discipline the host join uses applies one namespace over: ask
// about the handful of paths that are actually listening, and test membership
// against the package database rather than inverting it into an index.
package ctrpkg

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/chaugan/swinv/internal/pathnorm"
)

// Owner is the package that installed a path.
type Owner struct {
	Name    string
	Version string
	Type    string // deb, rpm, apk
	Arch    string
	PURL    string
}

// Release is a container's own operating system, from its /etc/os-release.
//
// It is not decoration: a container is a different operating system from its
// host -- one on the development machine is RHEL 8.10 on an Ubuntu 26.04
// server -- and which advisories apply to its packages is decided by this, not
// by the host's.
type Release struct {
	ID         string
	VersionID  string
	PrettyName string
}

// maxDBBytes caps every file read here.
//
// The filesystem being read belongs to the container, which means its contents
// are chosen by whatever is running inside it. A cap is the cheap half of not
// letting a hostile container decide how much memory an inventory scan uses;
// the other half is that nothing here follows a path the container supplied.
const maxDBBytes = 64 << 20

// ReadRelease reads a container's own os-release.
func ReadRelease(root string) Release {
	for _, name := range []string{"etc/os-release", "usr/lib/os-release"} {
		raw, err := readCapped(filepath.Join(root, name))
		if err != nil {
			continue
		}
		var r Release
		for _, line := range strings.Split(string(raw), "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			value = strings.Trim(value, `"'`)
			switch key {
			case "ID":
				r.ID = value
			case "VERSION_ID":
				r.VersionID = value
			case "PRETTY_NAME":
				r.PrettyName = value
			}
		}
		if r.ID != "" {
			return r
		}
	}
	return Release{}
}

// Probe returns, for each of paths, the package inside root that installed it.
//
// Paths absent from the result are not owned by any package the container's
// database knows about -- which is a finding, not a failure: it is software
// running in a container that the container's own package manager did not
// install.
func Probe(root string, paths []string, rel Release) map[string]Owner {
	if len(paths) == 0 {
		return nil
	}

	canon := pathnorm.UsrMerge(root)
	want := make(map[string]string, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		want[canon(path.Clean(p))] = p
	}
	if len(want) == 0 {
		return nil
	}

	out := make(map[string]Owner)
	for _, probe := range []func(string, map[string]string, func(string) string, Release, map[string]Owner){
		probeDpkg, probeApk, probeRPM,
	} {
		probe(root, want, canon, rel, out)
		if len(out) == len(want) {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// probeDpkg reads the per-package file lists dpkg keeps, then the version from
// the status file.
func probeDpkg(root string, want map[string]string, canon func(string) string, rel Release, out map[string]Owner) {
	infoDir := filepath.Join(root, "var", "lib", "dpkg", "info")
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		return
	}

	// package name -> the probed paths it owns
	hits := make(map[string][]string)
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".list")
		if !ok {
			continue
		}
		raw, err := readCapped(filepath.Join(infoDir, e.Name()))
		if err != nil {
			continue
		}
		// A multi-arch package's list is named "foo:amd64.list".
		name, _, _ = strings.Cut(name, ":")
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if asked, ok := want[canon(path.Clean(line))]; ok {
				hits[name] = append(hits[name], asked)
			}
		}
	}
	if len(hits) == 0 {
		return
	}

	for name, versionArch := range dpkgVersions(root, hits) {
		for _, asked := range hits[name] {
			if _, taken := out[asked]; taken {
				continue
			}
			out[asked] = Owner{
				Name: name, Version: versionArch[0], Arch: versionArch[1], Type: "deb",
				PURL: purl("deb", rel, name, versionArch[0], versionArch[1]),
			}
		}
	}
}

// dpkgVersions reads the versions of just the packages that matched, from the
// status file.
func dpkgVersions(root string, wanted map[string][]string) map[string][2]string {
	// #nosec G703 -- root is a /proc/<pid>/root prefix chosen by the caller and
	// every suffix here is a constant, so no part of this path comes from
	// anything the container controls. What the container *does* control is
	// what those paths resolve to, which is why every read is capped; see
	// maxDBBytes and SECURITY.md.
	f, err := os.Open(filepath.Join(root, "var", "lib", "dpkg", "status"))
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	out := make(map[string][2]string, len(wanted))
	var name, version, arch string
	flush := func() {
		if name != "" && version != "" {
			if _, ok := wanted[name]; ok {
				out[name] = [2]string{version, arch}
			}
		}
		name, version, arch = "", "", ""
	}

	scanner := bufio.NewScanner(io.LimitReader(f, maxDBBytes))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "Package: "):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		case strings.HasPrefix(line, "Version: "):
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		case strings.HasPrefix(line, "Architecture: "):
			arch = strings.TrimSpace(strings.TrimPrefix(line, "Architecture: "))
		}
	}
	flush()
	return out
}

// probeApk reads Alpine's single installed-package database, where each record
// lists its own files.
//
// The format is one record per blank-line-separated block: "P:" the name, "V:"
// the version, "A:" the architecture, then directories as "F:" with the files
// under each as "R:".
func probeApk(root string, want map[string]string, canon func(string) string, rel Release, out map[string]Owner) {
	// #nosec G703 -- constant suffix under a caller-chosen root; see dpkgVersions.
	f, err := os.Open(filepath.Join(root, "lib", "apk", "db", "installed"))
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	var name, version, arch, dir string
	var owned []string
	flush := func() {
		for _, asked := range owned {
			if _, taken := out[asked]; !taken && name != "" {
				out[asked] = Owner{
					Name: name, Version: version, Arch: arch, Type: "apk",
					PURL: purl("apk", rel, name, version, arch),
				}
			}
		}
		name, version, arch, dir, owned = "", "", "", "", nil
	}

	scanner := bufio.NewScanner(io.LimitReader(f, maxDBBytes))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		value := line[2:]
		switch line[0] {
		case 'P':
			name = value
		case 'V':
			version = value
		case 'A':
			arch = value
		case 'F':
			dir = value
		case 'R':
			if asked, ok := want[canon("/"+path.Join(dir, value))]; ok {
				owned = append(owned, asked)
			}
		}
	}
	flush()
}

// purl renders the package URL the way the ecosystem's consumers expect,
// scoped to the container's own distribution rather than the host's.
func purl(typ string, rel Release, name, version, arch string) string {
	if name == "" || version == "" {
		return ""
	}
	namespace := rel.ID
	out := "pkg:" + typ + "/"
	if namespace != "" {
		out += namespace + "/"
	}
	out += name + "@" + version

	var qualifiers []string
	if arch != "" {
		qualifiers = append(qualifiers, "arch="+arch)
	}
	if rel.ID != "" && rel.VersionID != "" {
		qualifiers = append(qualifiers, "distro="+rel.ID+"-"+rel.VersionID)
	}
	if len(qualifiers) > 0 {
		out += "?" + strings.Join(qualifiers, "&")
	}
	return out
}

// readCapped reads a file, refusing anything implausibly large.
func readCapped(name string) ([]byte, error) {
	// #nosec G304,G703 -- every caller composes name from a constant suffix
	// under a root it chose; the read is capped and non-regular files refused.
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	return io.ReadAll(io.LimitReader(f, maxDBBytes))
}
