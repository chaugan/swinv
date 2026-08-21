package wincollect

import "testing"

func TestPreferredVersion(t *testing.T) {
	cases := []struct {
		name              string
		file, fixed, want string
	}{
		// The real .NET runtime string, from a developer laptop. Comma
		// separators and a git commit appended.
		{"dotnet runtime",
			"10,0,426,10301 @Commit: ae01d702098bc86408660b0c8933096a5f7ede3f",
			"10.0.426.10301", "10.0.426.10301"},

		// Microsoft system DLLs append a build tag in parentheses.
		{"windows system dll",
			"10.0.19041.1 (WinBuild.160101.0800)", "10.0.19041.1", "10.0.19041.1"},

		// The common case: a clean string, preferred over the numeric form
		// because it is what the vendor calls the release.
		{"clean", "1.2.3", "1.2.3.0", "1.2.3"},

		// A pre-release suffix is exactly what the numeric form cannot carry,
		// so it must survive.
		{"prerelease", "1.2.3-rc1", "1.2.3.0", "1.2.3-rc1"},

		{"no file version", "", "6.7.2.0", "6.7.2.0"},
		{"numeric is all zeroes", "", "0.0.0.0", ""},
		{"neither", "", "", ""},

		// A word where a version should be: fall back rather than report it.
		{"not a version at all", "unknown", "3.1.0.0", "3.1.0.0"},

		// Nothing usable anywhere: report the ugly string rather than nothing,
		// because a human reading the file is better served than by a blank.
		{"ugly with no fallback",
			"1,0,0,1 @Commit: abc", "", "1,0,0,1 @Commit: abc"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := preferredVersion(tc.file, tc.fixed); got != tc.want {
				t.Errorf("preferredVersion(%q, %q) = %q, want %q",
					tc.file, tc.fixed, got, tc.want)
			}
		})
	}
}

func TestUsableVersion(t *testing.T) {
	for _, ok := range []string{"1.2.3", "1.2.3.4", "1.2.3-rc1", "2024.1", "1.0.0+build7"} {
		if !usableVersion(ok) {
			t.Errorf("usableVersion(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{
		"", "unknown", "1, 2, 3", "1,0,0,1", "1.0 beta", "10.0.19041.1 (WinBuild)",
	} {
		if usableVersion(bad) {
			t.Errorf("usableVersion(%q) = true, want false", bad)
		}
	}
}
