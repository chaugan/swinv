package main

import "testing"

func TestDirectoryFromRegistryValue(t *testing.T) {
	// Real shapes these values take. Registry uninstall keys are written by
	// thousands of unrelated installers and are inconsistent in every way a
	// string can be.
	cases := map[string]string{
		`C:\Program Files\App\app.exe`:                `C:\Program Files\App`,
		`C:\Program Files\App\app.exe,0`:              `C:\Program Files\App`,
		`C:\Program Files\App\app.exe,-101`:           `C:\Program Files\App`,
		`"C:\Program Files\App\unins000.exe"`:         `C:\Program Files\App`,
		`"C:\Program Files\App\unins000.exe" /SILENT`: `C:\Program Files\App`,
		`C:\Program Files\App\unins.exe /S`:           `C:\Program Files\App`,
		`  C:\Qt\Tools\QtCreator\bin\qtcreator.exe  `: `C:\Qt\Tools\QtCreator\bin`,
		`C:/ProgramData/anaconda3/uninstall.exe`:      `C:\ProgramData\anaconda3`,
		`C:\Users\chris\AppData\Local\uv\uv.exe`:      `C:\Users\chris\AppData\Local\uv`,

		// Nothing recoverable.
		`MsiExec.exe /X{90160000-000F-0000-1000-0000000FF1CE}`: "",
		`msiexec /i {GUID}`:                        "",
		`rundll32.exe setupapi,InstallHinfSection`: "",
		``:    "",
		`   `: "",
		// A file at the volume root would make the allowlist the whole drive.
		`C:\app.exe`: "",
	}

	for in, want := range cases {
		if got := directoryFromRegistryValue(in); got != want {
			t.Errorf("directoryFromRegistryValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInstallLocationsPrefersInstallLocationAndDeduplicates(t *testing.T) {
	got := installLocations(
		`C:\Program Files\App\`,
		`C:\Program Files\App\app.exe,0`,
		`"C:\Program Files\App\unins.exe" /S`,
	)
	// All three name the same directory; it should appear once.
	if len(got) != 1 || got[0] != `C:\Program Files\App` {
		t.Fatalf("got %v, want one entry for the install directory", got)
	}

	// When InstallLocation is absent -- the common case -- the others carry it.
	got = installLocations("", `C:\Qt\Tools\QtCreator\bin\qtcreator.exe,0`, `MsiExec.exe /X{G}`)
	if len(got) != 1 || got[0] != `C:\Qt\Tools\QtCreator\bin` {
		t.Fatalf("got %v, want the directory recovered from DisplayIcon", got)
	}

	if got := installLocations("", "", "MsiExec.exe /X{G}"); len(got) != 0 {
		t.Errorf("got %v, want none: an MSI product code names no directory", got)
	}
}

func TestInstallLocationsIsCaseInsensitiveWhenDeduplicating(t *testing.T) {
	got := installLocations(`C:\Program Files\App`, `c:\program files\app\x.exe`, "")
	if len(got) != 1 {
		t.Errorf("got %v, want one: Windows paths differing only in case are the same directory", got)
	}
}
