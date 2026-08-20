// Package usn enumerates the files on an NTFS volume by reading Master File
// Table records through the change journal API, instead of by walking
// directories.
//
// The motivation is measured rather than theoretical. Syft's directory resolver
// finds files with filepath.Walk and then opens every regular file it sees to
// sniff a MIME type, before any cataloger runs. On Linux the page cache hides
// the cost. On Windows it cannot: Defender inspects a file when it is opened,
// cached or not, and a scan of C:\Program Files on a real machine did not
// finish inside ten minutes.
//
// FSCTL_ENUM_USN_DATA returns a record per file straight from the MFT. That
// changes three things at once:
//
//   - No directory traversal. Records arrive in MFT order, not tree order.
//   - No file is opened. A name-based filter can reject the majority of a tree
//     before a single handle exists, so the MIME sniff never happens for them
//     and neither does the antivirus interception it provokes.
//   - Cloud placeholders stay dehydrated. Walking a OneDrive folder and opening
//     its files downloads them; enumerating the MFT cannot, because it never
//     opens anything.
//
// What it does not do is remove the cost of reading the files that *are*
// interesting: a version still has to come out of the binary. This moves the
// bottleneck from every file to the candidates, which is the whole point.
//
// Enumeration requires an elevated process and an NTFS volume. Both are
// reported as typed errors so a caller can degrade rather than fail.
package usn

import (
	"context"
	"errors"
)

var (
	// ErrUnsupportedPlatform is returned on anything other than Windows.
	ErrUnsupportedPlatform = errors.New("usn: MFT enumeration is only available on Windows")

	// ErrNotNTFS is returned for a volume with no Master File Table. ReFS,
	// FAT32 and exFAT all reach this. There is no fallback here by design: the
	// caller decides whether to walk the tree the slow way, because that
	// decision belongs to the operator.
	ErrNotNTFS = errors.New("usn: volume is not NTFS and has no Master File Table")

	// ErrNotElevated is returned when the volume handle cannot be opened for
	// lack of privilege. Opening \\.\C: requires an elevated token; membership
	// of the Administrators group is not sufficient under UAC.
	ErrNotElevated = errors.New("usn: opening the volume requires an elevated process")
)

// Entry is one file or directory found in the MFT.
//
// There is no size or timestamp here even though a caller might want them:
// USN records do not carry either. Anything beyond identity and path costs a
// file open, which is exactly what this package exists to avoid.
type Entry struct {
	// Path is the full path with the volume prefix, e.g. `C:\Windows\notepad.exe`.
	// Empty when the parent chain could not be resolved -- see Result.Unresolved.
	Path string

	// Name is the file name alone, always present.
	Name string

	// IsDir reports FILE_ATTRIBUTE_DIRECTORY.
	IsDir bool

	// Attributes is the raw Windows file attribute bitmask, so a caller can
	// apply its own policy to reparse points, offline files and the like
	// without this package having to guess which matter.
	Attributes uint32

	// FileRef and ParentRef are MFT file reference numbers, kept because they
	// are the only stable identity a file has here.
	FileRef   uint64
	ParentRef uint64
}

// Options configures an enumeration.
type Options struct {
	// Volume is a drive specification such as "C:". A trailing separator is
	// tolerated.
	Volume string

	// Keep decides whether a file is returned. It is called with the name
	// only, before any path is reconstructed and without opening anything,
	// which is where the saving comes from: reject on extension and the file
	// costs nothing beyond the record already in hand.
	//
	// Directories are always retained internally regardless of Keep, because
	// path reconstruction needs them, but they are only *returned* if Keep
	// accepts them.
	//
	// A nil Keep returns everything, which on a system volume means a very
	// large slice. Prefer a filter.
	Keep func(name string, isDir bool, attributes uint32) bool
}

// Result is what an enumeration produced.
type Result struct {
	// Entries are the retained files and directories, in MFT order. MFT order
	// is not tree order and is not sorted; a caller that needs determinism
	// must sort.
	Entries []Entry

	// Records is how many MFT records were read in total, including those
	// rejected by Keep. The ratio of len(Entries) to Records is the saving
	// this package delivers over a directory walk.
	Records int

	// Directories is how many directory records were held for path
	// reconstruction. It bounds the memory this package needs, since
	// directories are the only thing retained unconditionally.
	Directories int

	// Unresolved counts entries whose parent chain could not be followed to
	// the volume root, so Path is empty. A non-zero value is not an error:
	// the MFT is enumerated live and a directory can be deleted between its
	// record being read and its child's.
	Unresolved int
}

// Enumerate reads every MFT record on a volume and returns those Keep accepts.
func Enumerate(ctx context.Context, opts Options) (*Result, error) {
	return enumerate(ctx, opts)
}
