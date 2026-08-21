package appx

import "testing"

// The full names below are verbatim from a real Windows Server 2025 machine.
func TestParseFullName(t *testing.T) {
	cases := []struct {
		in                         string
		name, version, arch, pubID string
		ok                         bool
	}{
		{"Microsoft.WindowsTerminal_3001.23.20211.0_neutral_~_8wekyb3d8bbwe",
			"Microsoft.WindowsTerminal", "3001.23.20211.0", "neutral", "8wekyb3d8bbwe", true},
		{"Microsoft.SecHealthUI_1000.29628.1000.0_x64__8wekyb3d8bbwe",
			"Microsoft.SecHealthUI", "1000.29628.1000.0", "x64", "8wekyb3d8bbwe", true},
		{"Microsoft.MicrosoftEdge.Stable_151.0.4129.93_neutral__8wekyb3d8bbwe",
			"Microsoft.MicrosoftEdge.Stable", "151.0.4129.93", "neutral", "8wekyb3d8bbwe", true},
		// System apps are named by GUID. Still a valid package.
		{"1527c705-839a-4832-9118-54d4Bd6a0c89_10.0.19640.1000_neutral_neutral_cw5n1h2txyewy",
			"1527c705-839a-4832-9118-54d4Bd6a0c89", "10.0.19640.1000", "neutral", "cw5n1h2txyewy", true},
		// Resource bundles parse; whether to keep them is a separate question.
		{"Microsoft.DesktopAppInstaller_1.26.510.0_neutral_split.scale-125_8wekyb3d8bbwe",
			"Microsoft.DesktopAppInstaller", "1.26.510.0", "neutral", "8wekyb3d8bbwe", true},

		// Not packages. WindowsApps also contains these directories.
		{"Deleted", "", "", "", "", false},
		{"Merged", "", "", "", "", false},
		{"", "", "", "", "", false},
		{"too_few_fields", "", "", "", "", false},
		{"_1.0_x64__hash", "", "", "", "", false},  // empty name
		{"Name__x64__hash", "", "", "", "", false}, // empty version
	}

	for _, tc := range cases {
		got, ok := parseFullName(tc.in)
		if ok != tc.ok {
			t.Errorf("parseFullName(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.Name != tc.name || got.Version != tc.version ||
			got.Architecture != tc.arch || got.PublisherID != tc.pubID {
			t.Errorf("parseFullName(%q) = %+v", tc.in, got)
		}
	}
}

// A single application ships one resource package per display scale and per
// language. Counting them turns one app into a dozen entries differing only in
// an asset resolution.
func TestIsResourcePackage(t *testing.T) {
	for _, a := range []string{"split.scale-100", "split.scale-125", "split.language-en"} {
		if !isResourcePackage(a) {
			t.Errorf("isResourcePackage(%q) = false, want true", a)
		}
	}
	for _, a := range []string{"x64", "neutral", "arm64", "x86", ""} {
		if isResourcePackage(a) {
			t.Errorf("isResourcePackage(%q) = true, want false", a)
		}
	}
}

func TestIsOperatingSystemApp(t *testing.T) {
	for _, p := range []string{
		`C:\Windows\SystemApps\Microsoft.Windows.FilePicker_cw5n1h2txyewy`,
		`c:\windows\systemapps\Microsoft.Windows.FileExplorer_cw5n1h2txyewy`,
		`C:\Windows\ImmersiveControlPanel`,
	} {
		if !isOperatingSystemApp(p) {
			t.Errorf("isOperatingSystemApp(%q) = false, want true", p)
		}
	}
	for _, p := range []string{
		`C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_3001.23.20211.0_x64__8wekyb3d8bbwe`,
		`D:\Program Files\WindowsApps\Something`,
		``,
	} {
		if isOperatingSystemApp(p) {
			t.Errorf("isOperatingSystemApp(%q) = true, want false", p)
		}
	}
}

// Verbatim CBS package names from a machine with 7,844 of them.
func TestKBFromCBSPackage(t *testing.T) {
	cases := map[string]string{
		"Package_10_for_KB5120708~31bf3856ad364e35~amd64~~10.0.9344.1":              "KB5120708",
		"Package_11_for_KB5120708~31bf3856ad364e35~amd64~~10.0.9344.1":              "KB5120708",
		"Package_for_KB5062553~31bf3856ad364e35~amd64~~26100.1.1.0":                 "KB5062553",
		"Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.1234.1.9":              "",
		"Microsoft-Windows-Foundation-Package~31bf3856ad364e35~amd64~~10.0.26100.1": "",
		"":     "",
		"KB12": "", // too short to be a real KB number
	}
	for in, want := range cases {
		if got := kbFromCBSPackage(in); got != want {
			t.Errorf("kbFromCBSPackage(%q) = %q, want %q", in, got, want)
		}
	}
}
