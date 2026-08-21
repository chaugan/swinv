package wincollect

import (
	"regexp"
	"strings"
)

// CPE is the only identifier a Windows component can carry.
//
// PURL is deliberately left empty: there is no canonical PURL type for an
// uninstall-registry row, and inventing one would create false confidence.
// That decision is sound and it left a hole, because without a PURL *and*
// without a CPE a component carries no identifier at all -- so a CycloneDX
// document from a Windows host matches nothing in any vulnerability scanner.
// It looks like a clean result and is an empty one.
//
// CPE is what the gap wants. It was designed for exactly this: commercial and
// proprietary software with no package manager behind it, identified by vendor
// and product name.
//
// These are candidates, not facts. Vendor and product naming in the uninstall
// registry is written by thousands of unrelated installers and rarely matches
// the NVD's spelling, so several plausible forms are emitted rather than one
// confident guess. The failure mode is a miss, not a false match: a CPE only
// matches when both vendor and product hit, so a wrong guess finds nothing
// rather than finding the wrong thing.

// corporateSuffixes are dropped from a publisher name. The NVD records Chrome
// under "google", not "google_llc", and every vendor writes its own legal
// suffix differently.
var corporateSuffixes = map[string]bool{
	"inc": true, "inc.": true, "incorporated": true,
	"corp": true, "corp.": true, "corporation": true,
	"llc": true, "l.l.c.": true, "ltd": true, "ltd.": true, "limited": true,
	"gmbh": true, "ag": true, "ab": true, "oy": true, "plc": true,
	"co": true, "co.": true, "company": true, "sa": true, "s.a.": true,
	"srl": true, "bv": true, "b.v.": true, "nv": true, "pty": true,
}

// cpeToken normalises a name into the character set a CPE 2.3 formatted string
// can carry unescaped: lowercase letters, digits, dot, underscore and hyphen.
//
// Anything else becomes an underscore rather than being escaped. Escaping is
// correct per the specification and is a reliable source of mismatches, since
// consumers vary in how they unescape; a restricted alphabet cannot be got
// wrong.
func cpeToken(s string) string {
	var b strings.Builder
	lastUnderscore := false

	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-':
			b.WriteRune(r)
			lastUnderscore = false
		case !lastUnderscore && b.Len() > 0:
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_-.")
}

// vendorCandidates turns a publisher into the forms the NVD might use.
func vendorCandidates(publisher string) []string {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(publisher)))
	if len(fields) == 0 {
		return nil
	}

	// Drop trailing legal suffixes: "Google LLC" -> "google",
	// "NVIDIA Corporation" -> "nvidia".
	trimmed := fields
	for len(trimmed) > 1 && corporateSuffixes[trimmed[len(trimmed)-1]] {
		trimmed = trimmed[:len(trimmed)-1]
	}

	var out []string
	add := func(s string) {
		if s = cpeToken(s); s != "" && !contains(out, s) {
			out = append(out, s)
		}
	}
	add(strings.Join(trimmed, " "))
	add(trimmed[0])                // "the_document_foundation" -> "the"
	add(strings.Join(fields, " ")) // the untouched form, in case the suffix is real
	return out
}

// productCandidates turns a display name into the forms the NVD might use.
func productCandidates(name string, vendors []string) []string {
	var out []string
	add := func(s string) {
		if s = cpeToken(s); s != "" && !meaningless(s) && !contains(out, s) {
			out = append(out, s)
		}
	}
	// The stripped form first: it is the one the NVD is most likely to hold.
	if stripped := stripVersionAndArch(name); stripped != "" && stripped != name {
		add(stripped)
	}
	add(name)

	// "Google Chrome" is recorded as google:chrome, not google:google_chrome.
	// Dropping a leading vendor word is the single most productive variant.
	lower := strings.ToLower(stripVersionAndArch(name))
	if lower == "" {
		lower = strings.ToLower(strings.TrimSpace(name))
	}
	for _, v := range vendors {
		prefix := strings.ReplaceAll(v, "_", " ") + " "
		if strings.HasPrefix(lower, prefix) {
			add(lower[len(prefix):])
		}
	}

	// "Microsoft.WindowsTerminal" -- an MSIX package name is dotted rather
	// than spaced, and everything after the *first* dot is the product.
	//
	// Not the last component. "Microsoft.UI.Xaml.2.8" ends in "8", and a CPE
	// with product "8" is worse than none: it is well-formed, looks like an
	// identifier, and denotes nothing.
	if i := strings.Index(name, "."); i > 0 && !strings.Contains(name, " ") {
		add(name[i+1:])
	}
	return out
}

// meaningless rejects product tokens that are only digits and separators.
//
// A version fragment is not a product name, and a CPE built from one is
// well-formed and denotes nothing -- which is worse than emitting nothing,
// because it looks like an identifier to anything downstream.
func meaningless(token string) bool {
	for _, r := range token {
		if r >= 'a' && r <= 'z' {
			return false
		}
	}
	return true
}

// archSuffix matches the architecture markers installers append to a display
// name: "(x64)", "(64-bit)", "- x86". They are not part of the product.
var archSuffix = regexp.MustCompile(`(?i)[\s\-_]*[\(\[]?\s*(x64|x86|amd64|arm64|ia64|32[\s\-]?bit|64[\s\-]?bit)\s*[\)\]]?\s*$`)

// trailingVersion matches a version number at the end of a display name:
// "7-Zip 24.08", "LibreOffice 24.8.4.2", "Node.js - 20.11.0".
var trailingVersion = regexp.MustCompile(`(?i)[\s\-]+v?\d+(\.\d+)*([\s\-]?(beta|rc|alpha)\d*)?\s*$`)

// stripVersionAndArch recovers the product from a display name.
//
// Uninstall entries mash product, version and architecture into one string --
// "7-Zip 24.08 (x64)" -- and a CPE built from that whole string matches
// nothing, because the NVD records the product alone. This was the specific
// weakness a downstream consumer pointed out: matching the display name
// against a CPE dictionary means stripping the version and architecture back
// out, which is guesswork the producer is better placed to do.
//
// Applied repeatedly, because both suffixes can be present in either order,
// and stopping when nothing more comes off so a name that is entirely version
// -like is not reduced to nothing.
func stripVersionAndArch(name string) string {
	for i := 0; i < 4; i++ {
		before := name
		name = strings.TrimSpace(archSuffix.ReplaceAllString(name, ""))
		name = strings.TrimSpace(trailingVersion.ReplaceAllString(name, ""))
		if name == before || name == "" {
			break
		}
	}
	return strings.Trim(strings.TrimSpace(name), "-_ ")
}

// candidateCPEs builds CPE 2.3 strings for a component.
//
// Capped deliberately. Each candidate is a guess, and a long list of guesses
// reads as thoroughness while being noise: the first few carry nearly all the
// probability of a hit.
func candidateCPEs(publisher, name, version string) []string {
	vendors := vendorCandidates(publisher)
	if len(vendors) == 0 {
		return nil
	}
	products := productCandidates(name, vendors)
	if len(products) == 0 {
		return nil
	}

	v := cpeToken(version)
	if v == "" {
		v = "*"
	}

	const maxCandidates = 4
	var out []string
	for _, product := range products {
		for _, vendor := range vendors {
			cpe := "cpe:2.3:a:" + vendor + ":" + product + ":" + v + ":*:*:*:*:*:*:*"
			if !contains(out, cpe) {
				out = append(out, cpe)
			}
			if len(out) >= maxCandidates {
				return out
			}
		}
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
