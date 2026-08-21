package appx

import "testing"

// The package names below are verbatim from two real machines: a Windows 11
// 25H2 laptop and a Windows Server 2025 runner.
func TestParseServicingPackage(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		kind        Kind
		version, kb string
		ok          bool
	}{
		{"the cumulative update carries no KB, only the build and UBR",
			"Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.33296.1.21",
			KindCumulative, "26100.33296", "", true},
		{"the staged checkpoint baseline parses the same way",
			"Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.1742.1.10",
			KindCumulative, "26100.1742", "", true},
		{"servicing stack update",
			"Package_for_ServicingStack_33288~31bf3856ad364e35~amd64~~26100.33288.1.4",
			KindServicingStack, "26100.33288", "", true},
		{"dotnet rollup keeps its own version, which is not the OS build",
			"Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9344.1",
			KindDotNetRollup, "10.0.9344.1", "", true},
		{"an enablement package is identified by its KB",
			"Package_for_KB5054156~31bf3856ad364e35~amd64~~26100.1.1.0",
			KindStandalone, "", "KB5054156", true},
		{"a rollup child carries the rollup's KB",
			"Package_10_for_KB5120708~31bf3856ad364e35~amd64~~10.0.9344.1",
			KindStandalone, "", "KB5120708", true},

		// The thousands of things in the store that are not updates.
		{"inbox component", "Microsoft-Windows-Foundation-Package~31bf3856ad364e35~amd64~~10.0.26100.1", "", "", "", false},
		{"language pack", "Microsoft-Windows-Client-LanguagePack-Package~31bf3856ad364e35~amd64~en-US~10.0.26100.1", "", "", "", false},
		{"not a package name at all", "nonsense", "", "", "", false},
		{"empty", "", "", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseServicingPackage(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			if got.Kind != tc.kind || got.Version != tc.version || got.KB != tc.kb {
				t.Errorf("got %+v, want kind=%s version=%q kb=%q", got, tc.kind, tc.version, tc.kb)
			}
		})
	}
}

// TestInstalledStateExcludesSuperseded pins the bug that made swinv report two
// .NET rollups a real machine had already replaced: superseded packages stay in
// the component store, and reading only key names cannot tell them apart from
// current ones.
func TestInstalledStateExcludesSuperseded(t *testing.T) {
	installed := map[uint64]bool{
		0x60: true,  // install pending
		0x65: true,  // partially installed
		0x70: true,  // installed
		0x80: true,  // permanent
		0x40: false, // staged -- the checkpoint baseline is one of these
		0x50: false, // superseded -- the May and July .NET rollups were these
		0x00: false,
		0x20: false,
	}
	for state, want := range installed {
		if got := isInstalledState(state); got != want {
			t.Errorf("isInstalledState(0x%X) = %v, want %v", state, got, want)
		}
	}
}

// A machine between installing an update and rebooting reports a patch level
// its running kernel does not have. An unattended scan lands in that window
// regularly.
func TestPendingState(t *testing.T) {
	for _, s := range []uint64{0x60, 0x65} {
		if !isPendingState(s) {
			t.Errorf("isPendingState(0x%X) = false, want true", s)
		}
	}
	for _, s := range []uint64{0x40, 0x50, 0x70, 0x80} {
		if isPendingState(s) {
			t.Errorf("isPendingState(0x%X) = true, want false", s)
		}
	}
}

func TestBuildAndUBR(t *testing.T) {
	cases := map[string]string{
		"26100.33296.1.21": "26100.33296",
		"26200.9168.1.9":   "26200.9168",
		"26100.1.1.0":      "26100.1",
		"26100":            "26100",
		"":                 "",
	}
	for in, want := range cases {
		if got := buildAndUBR(in); got != want {
			t.Errorf("buildAndUBR(%q) = %q, want %q", in, got, want)
		}
	}
}
