package wincollect

import "testing"

func TestClassifyRole(t *testing.T) {
	cases := []struct {
		name       string
		base, desc string
		orig, prod string
		wantRole   string
	}{
		// The reported case: Mozilla's stub says ProductName "Firefox", but
		// its description and filename give it away.
		{"firefox setup", "Firefox Setup 121.0.exe", "Firefox Installer", "Firefox Installer.exe", "Firefox", "installer"},
		{"firefox stub by name only", "helper.exe", "", "", "Firefox Installer", "installer"},
		{"generic setup filename", "AppSetup.exe", "", "", "Some App", "installer"},
		{"underscore installer", "node-v20_installer.exe", "", "", "", "installer"},
		{"vc redist", "vc_redist.x64.exe", "", "", "Microsoft Visual C++", "installer"},
		{"inno description", "app.exe", "Setup", "", "My App", "installer"},
		// The reported case exactly: renamed on disk, but the 7-Zip SFX
		// original_filename and version 18.05 give it away.
		{"7zip sfx stub", "Firefox Installer.exe", "Firefox", "7zS.sfx.exe", "Firefox", "installer"},
		{"7zip sfx renamed", "totally-legit.exe", "Firefox", "7zSD.sfx.exe", "Firefox", "installer"},

		// The real application must NOT trip: firefox.exe is Firefox.
		{"real firefox", "firefox.exe", "Firefox", "firefox.exe", "Firefox", ""},
		{"real chrome", "chrome.exe", "Google Chrome", "chrome.exe", "Google Chrome", ""},

		// Launcher shims: carry the app's ProductName, are not the app.
		{"firefox desktop launcher", "Firefox.exe", "", "desktop-launcher.exe", "Firefox", "launcher"},
		{"renamed desktop launcher", "Firefox-fnaskZenbook.exe", "", "desktop-launcher.exe", "Firefox", "launcher"},

		// Standalone / portable single-exe apps must NOT be flagged: no
		// installer, original_filename is their own name.
		{"portable tool", "SuperTool.exe", "SuperTool", "SuperTool.exe", "SuperTool", ""},
		{"portable renamed by user", "my-tool.exe", "SuperTool", "SuperTool.exe", "SuperTool", ""},
		{"standalone with no version fields", "widget.exe", "", "widget.exe", "Widget", ""},
		{"reinstallation word", "reinstaller_tool.exe", "Reinstallation report generator", "", "Report Tool", ""},
		{"setup substring in word", "presetupdb.dll", "Preset up database", "", "Preset Manager", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			role, why := classifyRole(c.base, c.desc, c.orig, c.prod)
			if role != c.wantRole {
				t.Errorf("classifyRole(%q, %q, %q, %q) = %q (%q), want %q",
					c.base, c.desc, c.orig, c.prod, role, why, c.wantRole)
			}
			if role != "" && why == "" {
				t.Error("a role was assigned with no evidence")
			}
		})
	}
}
