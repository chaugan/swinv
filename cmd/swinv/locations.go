package main

import "strings"

// directoryFromRegistryValue recovers an install directory from a registry
// value that points at a file inside it -- DisplayIcon or UninstallString.
//
// This exists because InstallLocation is mostly absent: on a real machine only
// 106 of 380 uninstall entries had one, so an allowlist derived from that field
// alone starts with 72% of installed products contributing nothing. Both of
// these values usually name an executable in the install directory, which is
// the same information by a less direct route.
//
// Returns an empty string when nothing usable can be recovered, which is the
// common case for MSI products whose UninstallString is just msiexec with a
// product code.
func directoryFromRegistryValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}

	// A quoted path may contain spaces and be followed by arguments:
	//   "C:\Program Files\App\unins.exe" /SILENT
	if strings.HasPrefix(v, `"`) {
		if end := strings.Index(v[1:], `"`); end >= 0 {
			v = v[1 : end+1]
		} else {
			v = v[1:]
		}
	} else if i := strings.Index(v, `" `); i >= 0 {
		v = v[:i]
	}

	// DisplayIcon appends an icon index: C:\App\app.exe,0
	if i := strings.LastIndex(v, ","); i > 0 && !strings.Contains(v[i:], `\`) {
		v = v[:i]
	}

	v = strings.TrimSpace(v)

	// MsiExec /X{GUID} names no directory. Neither does rundll32 and friends.
	// Requiring a drive letter rejects those without having to enumerate them.
	if len(v) < 3 || v[1] != ':' || (v[2] != '\\' && v[2] != '/') {
		return ""
	}

	// An unquoted value with arguments: keep only up to the first executable
	// extension, since a path with spaces cannot otherwise be told from a path
	// followed by a flag.
	lower := strings.ToLower(v)
	for _, ext := range []string{".exe", ".dll", ".msi", ".ico", ".cmd", ".bat"} {
		if i := strings.Index(lower, ext); i >= 0 {
			v = v[:i+len(ext)]
			break
		}
	}

	dir := windowsDir(v)
	if len(dir) < 4 {
		// "C:" or "C:\" -- the volume root. Allowing it would make the
		// allowlist match the whole drive, which is the opposite of the point.
		return ""
	}
	return dir
}

// windowsDir returns the directory part of a Windows path.
//
// filepath.Dir cannot be used: this code has to give the same answer whichever
// platform it is compiled for, and on anything but Windows filepath treats a
// backslash as an ordinary character, so filepath.Dir of a Windows path returns
// ".". Keeping the logic host-independent is what lets it be tested on the
// machine it is written on rather than only in CI.
func windowsDir(path string) string {
	path = strings.ReplaceAll(path, "/", `\`)
	i := strings.LastIndex(path, `\`)
	if i < 0 {
		return ""
	}
	return strings.TrimRight(path[:i], `\`)
}

// installLocations gathers candidate directories for one uninstall entry, most
// authoritative first.
func installLocations(installLocation, displayIcon, uninstallString string) []string {
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		for _, existing := range out {
			if strings.EqualFold(existing, s) {
				return
			}
		}
		out = append(out, s)
	}

	add(strings.TrimRight(strings.TrimSpace(installLocation), `\`))
	add(directoryFromRegistryValue(displayIcon))
	add(directoryFromRegistryValue(uninstallString))
	return out
}
