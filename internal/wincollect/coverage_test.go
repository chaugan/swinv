package wincollect

import "testing"

func TestUnderLocation(t *testing.T) {
	const loc = `C:\Program Files\Qt`

	in := []string{
		`C:\Program Files\Qt\bin\qt.dll`,
		`c:\program files\qt\bin\qt.dll`, // Windows paths are case-insensitive
		`C:\Program Files\Qt\6.7.2\msvc\lib.dll`,
	}
	for _, p := range in {
		if !UnderLocation(p, loc) {
			t.Errorf("UnderLocation(%q, %q) = false, want true", p, loc)
		}
	}

	out := []string{
		// The boundary case that matters: a plain prefix match would call
		// this covered and overstate the result.
		`C:\Program Files\QtCreator\bin\x.dll`,
		`C:\Program Files\Qt2\bin\x.dll`,
		`C:\Program Files\Other\qt.dll`,
		`C:\Program Files\Qt`, // the directory itself is not a file within it
		`D:\Program Files\Qt\bin\x.dll`,
	}
	for _, p := range out {
		if UnderLocation(p, loc) {
			t.Errorf("UnderLocation(%q, %q) = true, want false", p, loc)
		}
	}

	if UnderLocation(`C:\anything`, "") {
		t.Error("an empty location must match nothing; many uninstall keys have no InstallLocation")
	}
}

func TestUnderLocationTolerantOfTrailingSeparator(t *testing.T) {
	// Installers write InstallLocation both ways, frequently within the same
	// machine.
	for _, loc := range []string{`C:\Program Files\Qt`, `C:\Program Files\Qt\`} {
		if !UnderLocation(`C:\Program Files\Qt\bin\qt.dll`, loc) {
			t.Errorf("location %q did not match", loc)
		}
	}
}

func TestCoverageOfAttributesToLongestLocation(t *testing.T) {
	paths := []string{
		`C:\Program Files\Qt\bin\qt.dll`,
		`C:\Program Files\Other\a.dll`,
		`C:\Windows\WinSxS\x\b.dll`, // covered by nothing
	}
	locations := []string{`C:\Program Files`, `C:\Program Files\Qt`}

	covered, by := CoverageOf(paths, locations)
	if covered != 2 {
		t.Fatalf("covered = %d, want 2", covered)
	}
	// The Qt binary must be credited to Qt, not to its parent, or per-product
	// attribution is meaningless.
	if by[`C:\Program Files\Qt`] != 1 {
		t.Errorf("Qt attributed %d, want 1: %v", by[`C:\Program Files\Qt`], by)
	}
	if by[`C:\Program Files`] != 1 {
		t.Errorf("Program Files attributed %d, want 1: %v", by[`C:\Program Files`], by)
	}
}

func TestCoverageOfWithNoLocations(t *testing.T) {
	covered, by := CoverageOf([]string{`C:\a\b.dll`}, nil)
	if covered != 0 || len(by) != 0 {
		t.Errorf("covered = %d, by = %v; want 0 and empty", covered, by)
	}
}

func TestOSOrStoreTerritory(t *testing.T) {
	inside := []string{
		`C:\Windows\WinSxS\amd64_x\y.dll`,
		`C:\Windows\System32\kernel32.dll`,
		`c:\windows\syswow64\x.dll`,
		`C:\Program Files\WindowsApps\Pkg_1.0\app.exe`,
		`C:\Program Files (x86)\WindowsApps\Pkg\app.exe`,
	}
	for _, p := range inside {
		if !OSOrStoreTerritory(p, "C:") {
			t.Errorf("%q should be OS or Store territory", p)
		}
	}

	outside := []string{
		`C:\Program Files\Siemens\x.dll`,
		`C:\Qt\6.7.2\msvc\bin\q.dll`,
		`C:\ProgramData\anaconda3\python.dll`,
		`C:\Users\chris\AppData\Local\uv\uv.exe`,
		// Not under \Windows\ despite the prefix.
		`C:\WindowsExtra\x.dll`,
	}
	for _, p := range outside {
		if OSOrStoreTerritory(p, "C:") {
			t.Errorf("%q should not be OS or Store territory", p)
		}
	}

	if !OSOrStoreTerritory(`D:\Windows\System32\x.dll`, `D:\`) {
		t.Error("a trailing separator on the volume must not break matching")
	}
}

func TestLocationSetMatchesMostSpecificAndKeepsCasing(t *testing.T) {
	set := NewLocationSet([]string{
		`C:\Program Files`,
		`C:\Program Files\Qt`,
		`c:\program files\qt`, // same location, different case
		``,
		`   `,
	})

	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2: empties dropped and case-duplicates merged", set.Len())
	}

	// The deepest match wins, and comes back as it was written.
	if got := set.Match(`C:\Program Files\Qt\bin\q.dll`); got != `C:\Program Files\Qt` {
		t.Errorf("Match = %q, want the Qt location in its original casing", got)
	}
	if got := set.Match(`C:\Program Files\Other\a.dll`); got != `C:\Program Files` {
		t.Errorf("Match = %q, want the Program Files location", got)
	}

	// The separator boundary still holds: QtCreator is not inside Qt.
	if got := set.Match(`C:\Program Files\QtCreator\x.dll`); got != `C:\Program Files` {
		t.Errorf("Match = %q; QtCreator must not match the Qt location", got)
	}

	for _, p := range []string{`D:\Program Files\Qt\x.dll`, `C:\Windows\x.dll`, `C:\Program Files`} {
		if set.Covers(p) && p != `C:\Program Files` {
			t.Errorf("Covers(%q) = true, want false", p)
		}
	}
}

func TestLocationSetEmpty(t *testing.T) {
	set := NewLocationSet(nil)
	if set.Len() != 0 || set.Covers(`C:\x\y.dll`) {
		t.Error("an empty set must match nothing")
	}
}
