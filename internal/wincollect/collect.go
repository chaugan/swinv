package wincollect

import (
	"context"
	"errors"

	"github.com/chaugan/swinv/internal/model"
)

// ErrUnsupportedPlatform is returned on anything other than Windows.
var ErrUnsupportedPlatform = errors.New("wincollect: Windows inventory requires Windows")

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
	// Packages is how many Store and MSIX packages were found.
	Packages int
	// Updates is how many distinct Windows updates the component store holds.
	Updates int
	// LanguagePackages is how many ecosystem packages were read from manifests.
	LanguagePackages int
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

	// Executables is every executable file the MFT enumeration saw - exe,
	// dll, sys, ocx, cpl, drv - regardless of whether it was attributed,
	// opened, or skipped as OS territory. It exists for the PE import-table
	// probe: the enumeration is the index of the machine's binaries, and
	// walking the filesystem a second time to rebuild it would be absurd.
	// Filled only under FullScan, because only the enumeration fills it.
	Executables []string

	// Incomplete is set when the caller asked for work that could not be
	// done -- --full-scan on a volume that could not be enumerated, for
	// instance. The registry inventory is still returned and still correct;
	// it is just not the inventory that was requested, and the caller should
	// exit 1 rather than 0 so an unattended run notices.
	Incomplete bool
}

// Collect assembles an inventory of the software installed on this machine.
func Collect(ctx context.Context, opts Options) (*Result, error) {
	return collect(ctx, opts)
}
