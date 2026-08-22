//go:build windows

package service

import (
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

// A Windows registry entry records the directory a product was installed
// into, never the executables under it. Without a containing-directory join,
// nothing on Windows can ever be attributed and every listener reports as
// unmanaged software -- which is what a CI run produced: 65 exposure rows,
// none identified.
func TestAttributeByInstallDirectoryOnWindows(t *testing.T) {
	inv := Inventory{Components: []model.Component{
		{Name: "PostgreSQL 16", Version: "16.2", Type: "windows",
			Locations: []string{`C:\Program Files\PostgreSQL\16`}},
		// A shorter, less specific claim on the same tree.
		{Name: "Adobe Lightroom", Version: "7.0", Type: "windows",
			Locations: []string{`C:\Program Files\Adobe`}},
		{Name: "Adobe Photoshop 2024", Version: "25.0", Type: "windows",
			Locations: []string{`C:\Program Files\Adobe\Adobe Photoshop 2024`}},
	}}

	svc := func(exe string) Service {
		return Service{
			Process:   Process{PID: 100, Exe: exe},
			Endpoints: []Endpoint{{Protocol: TCP, Address: "0.0.0.0", Port: 5432, Inode: 1}},
		}
	}

	got := Attribute([]Service{svc(`C:\Program Files\PostgreSQL\16\bin\postgres.exe`)}, inv, 0)[0]
	if len(got.Components) != 1 || got.Components[0] != "PostgreSQL 16@16.2" {
		t.Errorf("components = %v", got.Components)
	}
	// Weaker evidence than a package file list, and graded as such.
	if got.Confidence != model.ConfidenceMedium {
		t.Errorf("confidence = %q, want medium", got.Confidence)
	}

	// The longest matching directory wins, or Photoshop's executables would be
	// attributed to Lightroom.
	deep := Attribute([]Service{svc(`C:\Program Files\Adobe\Adobe Photoshop 2024\photoshop.exe`)}, inv, 0)[0]
	if len(deep.Components) != 1 || deep.Components[0] != "Adobe Photoshop 2024@25.0" {
		t.Errorf("components = %v, want the more specific product", deep.Components)
	}

	// Case differs between the registry and the process table often enough to
	// matter, and Windows paths are case-insensitive.
	mixed := Attribute([]Service{svc(`c:\program files\postgresql\16\bin\postgres.exe`)}, inv, 0)[0]
	if len(mixed.Components) != 1 {
		t.Errorf("a case-different path was not matched: %v", mixed.Components)
	}
}

// An operating-system binary is not "software nothing installed": it came with
// the operating system, which this inventory represents by the installed
// servicing updates. Reporting it as unmanaged would put several dozen false
// entries in front of anyone filtering for exactly that.
func TestAttributeMarksOperatingSystemComponents(t *testing.T) {
	inv := Inventory{}
	s := Service{
		Process:   Process{PID: 4, Exe: `C:\Windows\System32\svchost.exe`},
		Endpoints: []Endpoint{{Protocol: TCP, Address: "0.0.0.0", Port: 135, Inode: 1}},
	}

	got := Attribute([]Service{s}, inv, 0)[0]
	if !got.OSComponent {
		t.Error("a System32 binary was not marked as an operating-system component")
	}
	if len(got.Components) != 0 {
		t.Errorf("components = %v", got.Components)
	}
	if !containsSubstring(got.Evidence, "operating-system component") {
		t.Errorf("evidence = %v", got.Evidence)
	}

	// And something outside the system root keeps the unmanaged verdict, which
	// is the finding worth having.
	vendor := Service{
		Process:   Process{PID: 900, Exe: `C:\vendor\app.exe`},
		Endpoints: []Endpoint{{Protocol: TCP, Address: "0.0.0.0", Port: 9000, Inode: 2}},
	}
	other := Attribute([]Service{vendor}, inv, 0)[0]
	if other.OSComponent {
		t.Error("a vendor binary outside the system root was called an OS component")
	}
	if !containsSubstring(other.Evidence, "not installed") {
		t.Errorf("evidence = %v", other.Evidence)
	}
}

func TestIsOSComponent(t *testing.T) {
	for _, in := range []string{`C:\Windows\System32\svchost.exe`, `c:\windows\explorer.exe`} {
		if !IsOSComponent(in) {
			t.Errorf("IsOSComponent(%q) = false", in)
		}
	}
	for _, in := range []string{`C:\Program Files\x\y.exe`, `C:\WindowsApps\a.exe`, ""} {
		if IsOSComponent(in) {
			t.Errorf("IsOSComponent(%q) = true", in)
		}
	}
}
