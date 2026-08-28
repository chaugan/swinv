package wincollect

import (
	"regexp"
	"strings"
)

// An installer on disk is a real file, but it is not the software it installs.
// "Firefox Setup 121.0.exe" carries ProductName "Firefox" in its version
// resource, so without this it enters the inventory as an installed Firefox -
// and a vulnerability matcher then reports Firefox CVEs against a machine that
// may not run Firefox at all, or runs a different version. The installer's
// version is the installer's, not the application's; treating the two as one
// is a confident wrong answer.
//
// swinv does not drop the row - the file is genuinely present, and hiding it
// would be its own kind of lie. It flags it: role=installer, with the evidence
// that decided it, so a consumer can rank it last or exclude it from matching
// while still knowing it is there.

// installerDescription matches the version-resource fields an installer stub
// fills in. Word-boundaried so "reinstallation" or a product literally named
// "Setup" by nobody does not trip it; "installer" and "setup" as standalone
// words are the reliable markers, and Mozilla, Google, and the NSIS/Inno
// defaults all use one.
var installerDescription = regexp.MustCompile(`(?i)\b(installer|setup|install wizard|uninstaller|web installer)\b`)

// installerFilename matches the on-disk name an installer is downloaded or
// shipped as. The " Setup " infix ("Firefox Setup 121.0.exe") and the
// setup/install suffixes are the common shapes; the vendor-neutral
// "vcredist"/"vc_redist" and the *_setup/*-setup forms cover the rest.
var installerFilename = regexp.MustCompile(`(?i)((^|[ _\-])(setup|install|installer|uninstall|vc_redist|vcredist)([ _\-.]|$)|(setup|install|installer|uninstall)(\.[a-z0-9]+)?$)`)

// installerStubOriginalFilename matches the original_filename an installer
// stub carries even when the file on disk has been renamed. A 7-Zip
// self-extracting archive ("7zS.sfx.exe", "7zSD.sfx.exe") is what Mozilla and
// many others wrap an installer in; wextract is IExpress; nsis is the NSIS
// stub. This is the field that caught the reported case: "Firefox Installer.exe"
// carried original_filename "7zS.sfx.exe" and version 18.05 - the 7-Zip SFX's
// version, not Firefox's.
var installerStubOriginalFilename = regexp.MustCompile(`(?i)(7z[a-z]{0,3}\.sfx|wextract|nsis[0-9a-z]*\.exe|_?setup\.exe$|installer\.exe$)`)

// launcherStubOriginalFilename is a curated set of generic launcher and
// wrapper stub names. A launcher carries the ProductName of the application it
// starts but is not that application: "Firefox.exe" on a Desktop with
// original_filename "desktop-launcher.exe" and version 149.0.2 is a shim, not
// Firefox 149, and matching its version raises findings for software that may
// not be installed at that version at all.
//
// This is a NAME allowlist on purpose, and a short one. A standalone or
// portable application that ships as a single exe with no installer is a real
// installation, and its original_filename is its own product's name, not one
// of these - so it is never flagged. The rule fires only on names that are
// generic wrappers by convention and nothing an application would call itself.
var launcherStubOriginalFilename = map[string]bool{
	"desktop-launcher.exe": true,
	"launcher.exe":         true,
	"stub.exe":             true,
	"wrapper.exe":          true,
	"applauncher.exe":      true,
}

// classifyRole reports what a PE is if it is not the application it claims to
// be: an "installer", a "launcher", or "" for the ordinary case. The evidence
// names the field that decided it.
//
// The whole point is to protect the standalone case. A portable tool with no
// installer is a genuine installation and must return "" - so every rule here
// keys on a positive marker of installer-ness or a known wrapper name, never
// on the absence of one, and never on the file simply having been renamed.
func classifyRole(basename, fileDescription, originalFilename, productName string) (role, evidence string) {
	if m := installerDescription.FindString(fileDescription); m != "" {
		return "installer", "file description names it a " + strings.ToLower(m)
	}
	if m := installerDescription.FindString(originalFilename); m != "" {
		return "installer", "original filename names it a " + strings.ToLower(m)
	}
	// The stub the installer was built with, betrayed by original_filename
	// even when the file was renamed. The strongest single tell that the
	// version belongs to the wrapper, not the application.
	if installerStubOriginalFilename.MatchString(originalFilename) {
		return "installer", "built as a self-extracting installer stub (" + originalFilename + ")"
	}
	if installerFilename.MatchString(basename) {
		return "installer", "the file name is an installer's (" + basename + ")"
	}
	// ProductName only when it says "installer" outright - "Firefox Installer"
	// is one; "Firefox" is not, and must not be, or every application trips.
	if strings.Contains(strings.ToLower(productName), "installer") {
		return "installer", "product name is an installer's (" + productName + ")"
	}
	// A generic launcher/wrapper stub carrying an application's ProductName.
	if launcherStubOriginalFilename[strings.ToLower(strings.TrimSpace(originalFilename))] {
		return "launcher", "a launcher stub (" + originalFilename + "), not the application itself"
	}
	return "", ""
}
