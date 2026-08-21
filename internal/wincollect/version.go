package wincollect

import "strings"

// preferredVersion chooses which of a PE file's two version strings to report.
//
// A version resource carries both a free-text FileVersion, written by whoever
// built the binary, and a numeric FixedFileVersion of four 16-bit integers.
// The free-text one is usually better -- it can express "1.2.3-rc1", which the
// numeric one flattens to 1.2.3.0 -- and is usually what the vendor calls the
// release.
//
// Usually. On a real machine the .NET runtime writes:
//
//	10,0,426,10301 @Commit: ae01d702098bc86408660b0c8933096a5f7ede3f
//
// Comma-separated, with the git commit appended. Microsoft's own system DLLs
// write things like "10.0.19041.1 (WinBuild.160101.0800)". Neither is a
// version any consumer can join on, and a CVE matcher handed the first will
// match nothing while looking like it tried.
//
// So the rule is: take FileVersion when it looks like a version, and fall back
// to the numeric form when it does not. Whitespace and commas are the two
// reliable tells -- a version number contains neither -- and both of the real
// examples above are caught by them. The rejected string is not lost; it stays
// in the component's attributes as file_version.
func preferredVersion(fileVersion, fixedFileVersion string) string {
	if v := strings.TrimSpace(fileVersion); usableVersion(v) {
		return v
	}
	if v := strings.TrimSpace(fixedFileVersion); v != "" && v != "0.0.0.0" {
		return v
	}
	// Both unusable. An ugly version beats none at all: something is better
	// for a human reading the report, even where a matcher cannot use it.
	return strings.TrimSpace(fileVersion)
}

// usableVersion reports whether a free-text version string can be joined on.
func usableVersion(v string) bool {
	if v == "" {
		return false
	}
	if strings.ContainsAny(v, " \t,;") {
		// Commas are a separator some build systems use instead of dots;
		// whitespace means prose has been appended. Either way the string is
		// no longer a version.
		return false
	}
	// It must contain a digit. Some binaries put a word here.
	return strings.ContainsAny(v, "0123456789")
}
