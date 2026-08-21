package hostfacts

import "testing"

// TestWindowsMajorVersionUsesBuildNotProductName pins the trap this exists
// for: the registry's ProductName reads "Windows 10 Pro" on Windows 11, so any
// code trusting it reports a fleet of Windows 11 hosts as Windows 10.
func TestWindowsMajorVersionUsesBuildNotProductName(t *testing.T) {
	cases := map[string]string{
		"26100": "11", // Windows 11 24H2
		"22631": "11", // 23H2
		"22000": "11", // the first Windows 11 build
		"21999": "10", // one below
		"19045": "10", // Windows 10 22H2
		"17763": "10", // Server 2019
		"":      "",
		"abc":   "",
		"0":     "",
		"-1":    "",
	}
	for build, want := range cases {
		if got := windowsMajorVersion(build); got != want {
			t.Errorf("windowsMajorVersion(%q) = %q, want %q", build, got, want)
		}
	}
}

func TestWindowsPrettyNameCorrectsTheRegistry(t *testing.T) {
	cases := []struct {
		name                                 string
		product, displayVersion, build, want string
	}{
		{
			"windows 11 misreported as 10 by the registry",
			"Windows 10 Pro", "24H2", "26100",
			"Windows 11 Pro 24H2 (build 26100)",
		},
		{
			"genuine windows 10 left alone",
			"Windows 10 Pro", "22H2", "19045",
			"Windows 10 Pro 22H2 (build 19045)",
		},
		{
			"server editions are not rewritten",
			"Windows Server 2022 Standard", "21H2", "20348",
			"Windows Server 2022 Standard 21H2 (build 20348)",
		},
		{
			"no product name, build carries it",
			"", "", "26100",
			"Windows 11 (build 26100)",
		},
		{"nothing at all", "", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := windowsPrettyName(tc.product, tc.displayVersion, tc.build); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWindowsKernelRelease(t *testing.T) {
	cases := []struct {
		major, minor, build, ubr, want string
	}{
		{"10", "0", "26100", "1234", "10.0.26100.1234"},
		{"10", "0", "26100", "0", "10.0.26100"},
		{"10", "0", "26100", "", "10.0.26100"},
		{"", "", "19045", "5011", "10.0.19045.5011"},
		{"", "", "", "", "10.0"},
	}
	for _, tc := range cases {
		got := windowsKernelRelease(tc.major, tc.minor, tc.build, tc.ubr)
		if got != tc.want {
			t.Errorf("windowsKernelRelease(%q,%q,%q,%q) = %q, want %q",
				tc.major, tc.minor, tc.build, tc.ubr, got, tc.want)
		}
	}
}

// TestNormalizeMachineGUID checks the Windows machine identity comes out in the
// same shape as a Linux machine-id, so a fleet dataset can use one column.
func TestNormalizeMachineGUID(t *testing.T) {
	const want = "4b3c2d1e5f60718293a4b5c6d7e8f900"
	for _, in := range []string{
		"4b3c2d1e-5f60-7182-93a4-b5c6d7e8f900",
		"{4B3C2D1E-5F60-7182-93A4-B5C6D7E8F900}",
		"  4B3C2D1E-5F60-7182-93A4-B5C6D7E8F900  ",
	} {
		if got := normalizeMachineGUID(in); got != want {
			t.Errorf("normalizeMachineGUID(%q) = %q, want %q", in, got, want)
		}
	}

	// Anything that is not a GUID yields nothing rather than a mangled
	// identity, which would key a fleet dataset on garbage.
	for _, bad := range []string{"", "not-a-guid", "1234", "zzzzzzzz-5f60-7182-93a4-b5c6d7e8f900"} {
		if got := normalizeMachineGUID(bad); got != "" {
			t.Errorf("normalizeMachineGUID(%q) = %q, want empty", bad, got)
		}
	}
}

// TestDefaultRootIsTheSystemRoot runs on every platform and is the test that
// would have caught host facts being empty on Windows.
//
// "/" is the default value of --root everywhere, including on Windows where
// the collector ignores it. filepath.Clean turns it into "\" there, so
// comparing the cleaned value against the literal "/" is false -- and the
// consequence was not an error but a silently emptier report.
func TestDefaultRootIsTheSystemRoot(t *testing.T) {
	for _, in := range []string{"/", "", "   "} {
		if _, isSystemRoot := normalizeRoot(in); !isSystemRoot {
			t.Errorf("normalizeRoot(%q) did not recognise the system root", in)
		}
	}

	// An actual path must not be mistaken for it, or scanning a mounted image
	// would report the scanning machine's identity against the image's
	// contents.
	for _, in := range []string{"/mnt/image", "/host", "relative/path"} {
		if _, isSystemRoot := normalizeRoot(in); isSystemRoot {
			t.Errorf("normalizeRoot(%q) was mistaken for the system root", in)
		}
	}
}

// TestWindowsVersionIDDistinguishesServerFromClient pins a mis-bucketing that
// CI surfaced: its runner is Windows Server 2025, which shares build 26100
// with Windows 11 24H2, and the build alone reported it as Windows "11".
func TestWindowsVersionIDDistinguishesServerFromClient(t *testing.T) {
	cases := []struct {
		name                              string
		product, build, installType, want string
	}{
		{"server 2025 shares a build with windows 11",
			"Windows Server 2025 Datacenter", "26100", "Server", "2025"},
		{"server core is still a server",
			"Windows Server 2022 Standard", "20348", "Server Core", "2022"},
		{"server 2012 R2 keeps its R2",
			"Windows Server 2012 R2 Standard", "9600", "Server", "2012 R2"},
		{"client on the same build is 11",
			"Windows 10 Pro", "26100", "Client", "11"},
		{"older client",
			"Windows 10 Pro", "19045", "Client", "10"},
		{"no installation type falls back to the build",
			"Windows 10 Pro", "26100", "", "11"},
		{"a server with no year in its name falls back",
			"Windows Server", "26100", "Server", "11"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := windowsVersionID(tc.product, tc.build, tc.installType)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestWindowsPrettyNameLeavesServerNamesAlone: the "Windows 10 -> 11" rewrite
// exists for client editions whose registry name is wrong. A server name is
// already right and must not be touched.
func TestWindowsPrettyNameLeavesServerNamesAlone(t *testing.T) {
	got := windowsPrettyName("Windows Server 2025 Datacenter", "24H2", "26100")
	if want := "Windows Server 2025 Datacenter 24H2 (build 26100)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
