// Package peversion reads version information out of a Windows executable.
//
// This is the extraction step, and it is the only part of a Windows scan that
// opens a file. Everything before it -- the uninstall registry, MFT
// enumeration, attributing files to known products -- is metadata, and costs
// nothing. Opening a binary is where antivirus interception is paid, so the
// design spends the whole pipeline arranging for this to run on as few files as
// possible: on a measured machine, 19,549 of 99,919 candidates.
//
// It uses version.dll rather than parsing the PE resource directory by hand.
// The layout of VS_VERSIONINFO is awkward -- nested, padded to 32-bit
// boundaries, with UTF-16 keys -- and Windows already ships a correct parser
// for it.
package peversion

import (
	"errors"
	"fmt"
)

// ErrNoVersionInfo means the file has no version resource. This is ordinary
// rather than exceptional: plenty of shipped DLLs carry none, and a caller
// should treat it as "nothing to report" rather than as a failure.
var ErrNoVersionInfo = errors.New("peversion: file has no version resource")

// ErrUnsupportedPlatform is returned on anything other than Windows.
var ErrUnsupportedPlatform = errors.New("peversion: reading PE version resources requires Windows")

// Info is what a version resource can tell us about a binary.
//
// Every field is optional and frequently empty. These strings are written by
// whoever built the binary, are not validated by anything, and are inconsistent
// across vendors -- ProductVersion in particular is free text and routinely
// contains things like "10.0.19041.1 (WinBuild.160101.0800)".
type Info struct {
	ProductName      string
	CompanyName      string
	FileDescription  string
	OriginalFilename string
	LegalCopyright   string

	// FileVersion and ProductVersion as the author wrote them, free text.
	FileVersion    string
	ProductVersion string

	// FixedFileVersion is the numeric version from VS_FIXEDFILEINFO, formatted
	// as a.b.c.d. It is four 16-bit integers rather than a string, so unlike
	// the fields above it cannot be malformed -- which makes it the value to
	// prefer when the string form is missing or unparseable.
	FixedFileVersion string
}

// Empty reports whether nothing useful was found.
func (i Info) Empty() bool {
	return i.ProductName == "" && i.CompanyName == "" && i.FileDescription == "" &&
		i.OriginalFilename == "" && i.FileVersion == "" && i.ProductVersion == "" &&
		i.FixedFileVersion == ""
}

// Read extracts version information from the executable at path.
func Read(path string) (Info, error) { return read(path) }

// formatFixedVersion renders the four 16-bit fields of VS_FIXEDFILEINFO.
//
// The version is stored as two 32-bit words, each holding two 16-bit
// components in the order high-then-low. Getting the halves the wrong way
// round produces a version that looks entirely plausible -- 0.10.0.1 for
// 10.0.1.0 -- which is why this is a separate function with its own test
// rather than four inline shifts.
func formatFixedVersion(ms, ls uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ms>>16, ms&0xFFFF, ls>>16, ls&0xFFFF)
}
