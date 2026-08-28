package wincollect

import "testing"

func TestClassifyInstaller(t *testing.T) {
	cases := []struct {
		name        string
		base, desc  string
		orig, prod  string
		wantInstall bool
	}{
		// The reported case: Mozilla's stub says ProductName "Firefox", but
		// its description and filename give it away.
		{"firefox setup", "Firefox Setup 121.0.exe", "Firefox Installer", "Firefox Installer.exe", "Firefox", true},
		{"firefox stub by name only", "helper.exe", "", "", "Firefox Installer", true},
		{"generic setup filename", "AppSetup.exe", "", "", "Some App", true},
		{"underscore installer", "node-v20_installer.exe", "", "", "", true},
		{"vc redist", "vc_redist.x64.exe", "", "", "Microsoft Visual C++", true},
		{"inno description", "app.exe", "Setup", "", "My App", true},
		// The reported case exactly: renamed on disk, but the 7-Zip SFX
		// original_filename and version 18.05 give it away.
		{"7zip sfx stub", "Firefox Installer.exe", "Firefox", "7zS.sfx.exe", "Firefox", true},
		{"7zip sfx renamed", "totally-legit.exe", "Firefox", "7zSD.sfx.exe", "Firefox", true},

		// The real application must NOT trip: firefox.exe is Firefox.
		{"real firefox", "firefox.exe", "Firefox", "firefox.exe", "Firefox", false},
		{"real chrome", "chrome.exe", "Google Chrome", "chrome.exe", "Google Chrome", false},
		{"reinstallation word", "reinstaller_tool.exe", "Reinstallation report generator", "", "Report Tool", false},
		{"setup substring in word", "presetupdb.dll", "Preset up database", "", "Preset Manager", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, why := classifyInstaller(c.base, c.desc, c.orig, c.prod)
			if got != c.wantInstall {
				t.Errorf("classifyInstaller(%q, %q, %q, %q) = %v (%q), want %v",
					c.base, c.desc, c.orig, c.prod, got, why, c.wantInstall)
			}
			if got && why == "" {
				t.Error("an installer was flagged with no evidence")
			}
		})
	}
}
