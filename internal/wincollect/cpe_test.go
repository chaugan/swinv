package wincollect

import (
	"strings"
	"testing"
)

// TestCandidateCPEsHitTheRealNVDNames uses products whose CPE names are
// well known, because the whole value of this is matching what the NVD
// actually records -- not producing something CPE-shaped.
func TestCandidateCPEsHitTheRealNVDNames(t *testing.T) {
	cases := []struct {
		publisher, name, version string
		want                     string // the CPE the NVD really uses
	}{
		{"Google LLC", "Google Chrome", "141.0.7390.55", "cpe:2.3:a:google:chrome:141.0.7390.55:*:*:*:*:*:*:*"},
		{"Microsoft Corporation", "Microsoft Edge", "151.0.4129.93", "cpe:2.3:a:microsoft:edge:151.0.4129.93:*:*:*:*:*:*:*"},
		{"Mozilla", "Mozilla Firefox", "134.0", "cpe:2.3:a:mozilla:firefox:134.0:*:*:*:*:*:*:*"},
		{"Oracle Corporation", "Oracle VM VirtualBox", "7.0.14", "cpe:2.3:a:oracle:vm_virtualbox:7.0.14:*:*:*:*:*:*:*"},
		{"NVIDIA Corporation", "NVIDIA Control Panel", "8.1.969.0", "cpe:2.3:a:nvidia:control_panel:8.1.969.0:*:*:*:*:*:*:*"},
	}

	for _, tc := range cases {
		got := candidateCPEs(tc.publisher, tc.name, tc.version)
		if !contains(got, tc.want) {
			t.Errorf("%s / %s\n  got  %v\n  want to include %s", tc.publisher, tc.name, got, tc.want)
		}
	}
}

// The full name is kept as well as the trimmed one: the NVD is not consistent
// about which it uses, and a candidate list exists precisely because of that.
func TestCandidateCPEsKeepTheUntrimmedForm(t *testing.T) {
	got := candidateCPEs("Google LLC", "Google Chrome", "1.0")
	if !contains(got, "cpe:2.3:a:google:google_chrome:1.0:*:*:*:*:*:*:*") {
		t.Errorf("got %v, want the untrimmed product form too", got)
	}
}

func TestCandidateCPEsAreWellFormed(t *testing.T) {
	inputs := [][3]string{
		{"Igor Pavlov", "7-Zip 24.09 (x64)", "24.09"},
		{"The Document Foundation", "LibreOffice 24.8.4.2", "24.8.4.2"},
		{"Siemens AG", "Siemens NX (64-bit)", "2312.4000"},
		{"日本語ベンダー", "アプリ", "1.0"},
		{"Publisher, Inc.", `Weird "Name" <v2>`, "1.0-beta+1"},
	}
	for _, in := range inputs {
		for _, cpe := range candidateCPEs(in[0], in[1], in[2]) {
			parts := strings.Split(cpe, ":")
			if len(parts) != 13 {
				t.Errorf("%q has %d fields, a CPE 2.3 string has 13", cpe, len(parts))
			}
			if parts[0] != "cpe" || parts[1] != "2.3" || parts[2] != "a" {
				t.Errorf("%q has a bad prefix", cpe)
			}
			// The restricted alphabet exists so nothing ever needs escaping.
			for _, field := range parts[3:5] {
				for _, r := range field {
					ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
						r == '.' || r == '-' || r == '_' || r == '*'
					if !ok {
						t.Errorf("%q contains %q, which would need escaping", cpe, r)
					}
				}
			}
		}
	}
}

func TestCandidateCPEsGiveUpRatherThanGuess(t *testing.T) {
	// No publisher means no vendor, and a CPE with a wrong vendor matches
	// nothing anyway -- so emit none rather than something that looks like an
	// identifier.
	if got := candidateCPEs("", "Some Product", "1.0"); len(got) != 0 {
		t.Errorf("got %v, want none without a publisher", got)
	}
	if got := candidateCPEs("Vendor", "", "1.0"); len(got) != 0 {
		t.Errorf("got %v, want none without a product", got)
	}
	if got := candidateCPEs("!!!", "###", "1.0"); len(got) != 0 {
		t.Errorf("got %v, want none when nothing survives normalisation", got)
	}
}

func TestCandidateCPEsAreCapped(t *testing.T) {
	got := candidateCPEs("The Very Long Publisher Name Corporation", "The Very Long Publisher Name Product", "1.0")
	if len(got) > 4 {
		t.Errorf("got %d candidates, want at most 4: a long list of guesses reads as thoroughness and is noise", len(got))
	}
}

func TestCandidateCPEsHandleMSIXNames(t *testing.T) {
	// Appx package names are dotted rather than spaced.
	got := candidateCPEs("Microsoft Corporation", "Microsoft.WindowsTerminal", "1.24.11911.0")
	if !contains(got, "cpe:2.3:a:microsoft:windowsterminal:1.24.11911.0:*:*:*:*:*:*:*") {
		t.Errorf("got %v, want the last dotted component as the product", got)
	}
}

func TestCPEToken(t *testing.T) {
	cases := map[string]string{
		"Google Chrome":     "google_chrome",
		"7-Zip 24.09 (x64)": "7-zip_24.09_x64",
		"  Spaced  Out  ":   "spaced_out",
		"!!!":               "",
		"":                  "",
		"Already_fine-1.2":  "already_fine-1.2",
	}
	for in, want := range cases {
		if got := cpeToken(in); got != want {
			t.Errorf("cpeToken(%q) = %q, want %q", in, got, want)
		}
	}
}
