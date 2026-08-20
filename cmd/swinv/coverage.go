package main

import "strings"

// underLocation reports whether a file path lies inside an install location.
//
// Matching is case-insensitive, because Windows paths are, and it requires a
// separator boundary so that "C:\Program Files\Qt" does not swallow
// "C:\Program Files\QtCreator" -- a plain string prefix would, and would
// overstate coverage by exactly the amount that makes the measurement useless.
func underLocation(path, location string) bool {
	if location == "" {
		return false
	}
	path = strings.ToLower(path)
	location = strings.ToLower(strings.TrimRight(location, `\`))

	if !strings.HasPrefix(path, location) {
		return false
	}
	rest := path[len(location):]
	return strings.HasPrefix(rest, `\`)
}

// coverageOf counts how many paths fall under at least one install location,
// and attributes each covered path to the longest location that contains it.
//
// Longest wins so that a nested product is credited to itself rather than to
// its parent: with locations "C:\Program Files\Qt" and "C:\Program Files",
// a Qt binary belongs to Qt.
func coverageOf(paths, locations []string) (covered int, byLocation map[string]int) {
	byLocation = make(map[string]int)

	for _, p := range paths {
		best := ""
		for _, loc := range locations {
			if underLocation(p, loc) && len(loc) > len(best) {
				best = loc
			}
		}
		if best != "" {
			covered++
			byLocation[best]++
		}
	}
	return covered, byLocation
}

// osOrStoreTerritory reports whether a path belongs to software that should
// never have come from an uninstall-key allowlist in the first place.
//
// Everything under \Windows is an operating system component, serviced by
// Windows Update and inventoried through the component store and hotfix list.
// WindowsApps holds Store and MSIX packages, which are enumerated through the
// Appx API and deliberately have no uninstall key.
//
// Counting these against a registry-derived allowlist measures the wrong thing:
// they are not missing, they belong to a different source. The honest coverage
// figure is over what is left.
func osOrStoreTerritory(path, volume string) bool {
	lower := strings.ToLower(path)
	vol := strings.ToLower(strings.TrimRight(volume, `\`))

	for _, prefix := range []string{
		vol + `\windows\`,
		vol + `\program files\windowsapps\`,
		vol + `\program files (x86)\windowsapps\`,
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}
