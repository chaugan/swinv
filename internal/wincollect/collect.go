package wincollect

import (
	"context"
	"errors"

	"github.com/chaugan/swinv/internal/model"
)

// ErrUnsupportedPlatform is returned on anything other than Windows.
var ErrUnsupportedPlatform = errors.New("wincollect: Windows inventory requires Windows")

// Cataloger names, which appear in each component's found_by and are how a
// consumer tells where a fact came from.
const (
	registryCataloger = "windows-registry-cataloger"
	peCataloger       = "windows-pe-cataloger"
)

// Component types. Registry entries get "windows"; extracted executables reuse
// "binary", which already means the same thing on Linux.
const (
	typeWindows = "windows"
	typeBinary  = "binary"
)

// Options configures a Windows collection.
type Options struct {
	// Volumes to enumerate. Empty means C: alone. Naming volumes replaces the
	// default rather than adding to it.
	Volumes []string

	// FullScan enables MFT enumeration and extraction. Without it only the
	// registry is read, which is fast, needs no elevation, and covers
	// machine-wide installed software.
	FullScan bool

	// Parallelism is the number of concurrent extractions. Zero means a
	// conservative default: extraction is the one operation that costs, and
	// every open is intercepted by antivirus, so this is the dial that decides
	// how hard the scan leans on the machine.
	Parallelism int

	// Logf receives progress. Extraction of tens of thousands of files takes
	// minutes, and silence for minutes reads as a hang.
	Logf func(string, ...any)
}

// Stats records what each stage of the pipeline did, so the reduction the
// design depends on can be seen rather than assumed.
type Stats struct {
	// RegistryProducts is how many uninstall entries were read.
	RegistryProducts int
	// Enumerated is how many executables the MFT enumeration returned.
	Enumerated int
	// OSOrStore is how many were skipped as operating-system or Store
	// territory, which belong to catalogers that do not exist yet.
	OSOrStore int
	// Attributed is how many lay under a known product's install directory and
	// therefore needed no file opened.
	Attributed int
	// Opened is how many files were actually opened to extract a version.
	Opened int
	// NoVersionInfo is how many of those carried no version resource.
	NoVersionInfo int
}

// Result is a Windows inventory.
type Result struct {
	Components []model.Component
	Warnings   []string
	Stats      Stats
}

// Collect assembles an inventory of the software installed on this machine.
func Collect(ctx context.Context, opts Options) (*Result, error) {
	return collect(ctx, opts)
}
