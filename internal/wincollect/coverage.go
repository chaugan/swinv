package wincollect

import (
	"sort"
	"strings"
)

// UnderLocation reports whether a file path lies inside an install location.
//
// Matching is case-insensitive, because Windows paths are, and it requires a
// separator boundary so that "C:\Program Files\Qt" does not swallow
// "C:\Program Files\QtCreator" -- a plain string prefix would, and would
// overstate coverage by exactly the amount that makes the measurement useless.
func UnderLocation(path, location string) bool {
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

// CoverageOf counts how many paths fall under at least one install location,
// and attributes each covered path to the longest location that contains it.
//
// Longest wins so that a nested product is credited to itself rather than to
// its parent: with locations "C:\Program Files\Qt" and "C:\Program Files",
// a Qt binary belongs to Qt.
func CoverageOf(paths, locations []string) (covered int, byLocation map[string]int) {
	set := NewLocationSet(locations)
	byLocation = make(map[string]int)

	for _, p := range paths {
		if best := set.Match(p); best != "" {
			covered++
			byLocation[best]++
		}
	}
	return covered, byLocation
}

// OSOrStoreTerritory reports whether a path belongs to software that should
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
func OSOrStoreTerritory(path, volume string) bool {
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

// LocationSet answers "is this file inside a known product" for many files
// efficiently.
//
// The obvious implementation -- call UnderLocation for every (file, location)
// pair -- is 100,000 files against 150 locations, and lowercases the same
// location strings fifteen million times. Normalising once and sorting longest
// first turns that into a scan that stops at the first match, which is also the
// most specific one.
type LocationSet struct {
	// entries hold each location twice: lowercased for matching, and as
	// written for reporting. A caller showing which product a file belongs to
	// wants the operator's casing, not ours.
	entries []locationEntry
}

type locationEntry struct {
	lower    string
	original string
}

// NewLocationSet prepares locations for repeated matching. Empty entries and
// duplicates are dropped.
func NewLocationSet(locations []string) *LocationSet {
	seen := make(map[string]bool, len(locations))
	out := make([]locationEntry, 0, len(locations))

	for _, l := range locations {
		l = strings.TrimRight(strings.TrimSpace(l), `\`)
		lower := strings.ToLower(l)
		if lower == "" || seen[lower] {
			continue
		}
		seen[lower] = true
		out = append(out, locationEntry{lower: lower, original: l})
	}

	// Longest first, so the first match is the deepest one and a nested
	// product is credited to itself rather than to its parent.
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].lower) != len(out[j].lower) {
			return len(out[i].lower) > len(out[j].lower)
		}
		return out[i].lower < out[j].lower
	})
	return &LocationSet{entries: out}
}

// Match returns the most specific location containing path, as it was written,
// or "" if none does.
func (s *LocationSet) Match(path string) string {
	lower := strings.ToLower(path)
	for _, e := range s.entries {
		if len(lower) > len(e.lower) && lower[:len(e.lower)] == e.lower && lower[len(e.lower)] == '\\' {
			return e.original
		}
	}
	return ""
}

// Covers reports whether any location contains path.
func (s *LocationSet) Covers(path string) bool { return s.Match(path) != "" }

// Len is how many distinct locations the set holds.
func (s *LocationSet) Len() int { return len(s.entries) }
