package model

import "testing"

// A component with no PURL -- a Windows registry entry, for instance -- is
// still identifiable, and must stay identifiable in exactly one spelling: the
// CycloneDX dependency graph resolves these strings back to bom-refs.
func TestIdentifyFallsBackToNameAndVersion(t *testing.T) {
	cases := map[string]Component{
		"pkg:deb/x@1":         {Name: "x", Version: "1", PURL: "pkg:deb/x@1"},
		"Google Chrome@141.0": {Name: "Google Chrome", Version: "141.0"},
		"mystery":             {Name: "mystery"},
	}
	for want, c := range cases {
		if got := Identify(c); got != want {
			t.Errorf("Identify(%+v) = %q, want %q", c, got, want)
		}
	}
}
