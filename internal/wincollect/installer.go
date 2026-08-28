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

// classifyInstaller reports whether the PE at basename with these version
// strings is an installer, and the single piece of evidence that decided it.
//
// productName is checked last and most narrowly: a product legitimately named
// with "Setup" in it is rare, but "Installer" in a FileDescription is close to
// definitive, so the description and original-filename fields lead.
func classifyInstaller(basename, fileDescription, originalFilename, productName string) (bool, string) {
	if m := installerDescription.FindString(fileDescription); m != "" {
		return true, "file description names it a " + strings.ToLower(m)
	}
	if m := installerDescription.FindString(originalFilename); m != "" {
		return true, "original filename names it a " + strings.ToLower(m)
	}
	if installerFilename.MatchString(basename) {
		return true, "the file name is an installer's (" + basename + ")"
	}
	// ProductName only when it says "installer" outright - "Firefox Installer"
	// is one; "Firefox" is not, and must not be, or every application trips.
	if strings.Contains(strings.ToLower(productName), "installer") {
		return true, "product name is an installer's (" + productName + ")"
	}
	return false, ""
}
