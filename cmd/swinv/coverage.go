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
