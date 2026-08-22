package ctrpkg

import (
	"bufio"
	"bytes"
	"sort"
	"strings"
)

// ReadReleaseFrom reads a container's own operating system through a Source.
func ReadReleaseFrom(src Source) Release {
	for _, name := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		raw, err := src.ReadFile(name)
		if err != nil {
			continue
		}
		if r := parseRelease(raw); r.ID != "" {
			return r
		}
	}
	return Release{}
}

func parseRelease(raw []byte) Release {
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
	return r
}

// All lists every package a container's own database records.
//
// This is the answer where the targeted probe cannot be asked: a stopped
// container has no listening process, so there is no executable whose owner to
// look up, and the honest inventory of it is everything it contains. It is
// also the only answer available for a running container reached through a
// runtime API rather than through /proc, since that route gives no process
// paths either.
//
// Deliberately not used where a process *is* known. Naming the package behind
// a listening executable is a far stronger statement than listing the two
// hundred packages that happen to share its filesystem, and swinv prefers the
// stronger one wherever it can be made.
func All(src Source, rel Release) []Owner {
	if out := allDpkg(src, rel); len(out) > 0 {
		return out
	}
	if out := allApk(src, rel); len(out) > 0 {
		return out
	}
	return allRPM(src, rel)
}

// allDpkg reads every stanza of the dpkg status file.
func allDpkg(src Source, rel Release) []Owner {
	raw, err := src.ReadFile("/var/lib/dpkg/status")
	if err != nil {
		return nil
	}

	var out []Owner
	var name, version, arch, status string
	flush := func() {
		// Only what is actually installed. A "deinstall ok config-files"
		// stanza is a package whose files are gone and whose CVEs are not this
		// machine's problem.
		if name != "" && version != "" && strings.Contains(status, "installed") &&
			!strings.HasPrefix(status, "deinstall") {
			out = append(out, Owner{
				Name: name, Version: version, Arch: arch, Type: "deb",
				PURL: purl("deb", rel, name, version, arch),
			})
		}
		name, version, arch, status = "", "", "", ""
	}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
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
		case strings.HasPrefix(line, "Status: "):
			status = strings.TrimSpace(strings.TrimPrefix(line, "Status: "))
		}
	}
	flush()
	return sorted(out)
}

// allApk reads every record of Alpine's installed database.
func allApk(src Source, rel Release) []Owner {
	raw, err := src.ReadFile("/lib/apk/db/installed")
	if err != nil {
		return nil
	}

	var out []Owner
	var name, version, arch string
	flush := func() {
		if name != "" && version != "" {
			out = append(out, Owner{
				Name: name, Version: version, Arch: arch, Type: "apk",
				PURL: purl("apk", rel, name, version, arch),
			})
		}
		name, version, arch = "", "", ""
	}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
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
		switch line[0] {
		case 'P':
			name = line[2:]
		case 'V':
			version = line[2:]
		case 'A':
			arch = line[2:]
		}
	}
	flush()
	return sorted(out)
}

func sorted(in []Owner) []Owner {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Name != in[j].Name {
			return in[i].Name < in[j].Name
		}
		return in[i].Version < in[j].Version
	})
	return in
}
