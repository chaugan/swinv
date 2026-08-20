//go:build windows

package peversion

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fixedFileInfoSignature marks a valid VS_FIXEDFILEINFO. Checking it guards
// against treating an arbitrary buffer as a version structure, which would
// yield confident nonsense rather than an error.
const fixedFileInfoSignature = 0xFEEF04BD

// vsFixedFileInfo is VS_FIXEDFILEINFO. Only the leading fields are used; the
// rest describe file flags and target OS and say nothing about identity.
type vsFixedFileInfo struct {
	Signature        uint32
	StrucVersion     uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
}

// translation is one entry of \VarFileInfo\Translation: the language and code
// page under which the string table for this binary is filed.
type translation struct {
	Language uint16
	CodePage uint16
}

func read(path string) (Info, error) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil {
		// ERROR_RESOURCE_TYPE_NOT_FOUND and friends all mean the same thing to
		// a caller: there is no version resource here. Distinguishing them
		// would only give callers more ways to write the same check.
		return Info{}, fmt.Errorf("%w: %s", ErrNoVersionInfo, path)
	}
	if size == 0 {
		return Info{}, fmt.Errorf("%w: %s", ErrNoVersionInfo, path)
	}

	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return Info{}, fmt.Errorf("peversion: reading version info from %s: %w", path, err)
	}

	var info Info
	info.FixedFileVersion, info.ProductVersion = fixedVersions(buf)

	// The string table is filed under a language and code page, and the binary
	// declares which. Guessing the common 040904B0 works often enough to be
	// tempting and fails silently on anything localised, so ask.
	for _, t := range translations(buf) {
		prefix := fmt.Sprintf(`\StringFileInfo\%04x%04x\`, t.Language, t.CodePage)

		assignFirst(&info.ProductName, stringValue(buf, prefix+"ProductName"))
		assignFirst(&info.CompanyName, stringValue(buf, prefix+"CompanyName"))
		assignFirst(&info.FileDescription, stringValue(buf, prefix+"FileDescription"))
		assignFirst(&info.OriginalFilename, stringValue(buf, prefix+"OriginalFilename"))
		assignFirst(&info.LegalCopyright, stringValue(buf, prefix+"LegalCopyright"))
		assignFirst(&info.FileVersion, stringValue(buf, prefix+"FileVersion"))

		// A string ProductVersion is what the author wrote and is preferred
		// over the numeric one, which is often just the file version repeated.
		if v := stringValue(buf, prefix+"ProductVersion"); v != "" {
			info.ProductVersion = v
		}
	}

	if info.Empty() {
		return Info{}, fmt.Errorf("%w: %s", ErrNoVersionInfo, path)
	}
	return info, nil
}

// assignFirst keeps the first non-empty value seen. A binary can carry several
// translations; the first is the one the author listed first.
func assignFirst(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}

// fixedVersions reads VS_FIXEDFILEINFO, returning the file and product
// versions in numeric form.
func fixedVersions(buf []byte) (fileVersion, productVersion string) {
	var (
		ptr  unsafe.Pointer
		size uint32
	)
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`,
		unsafe.Pointer(&ptr), &size); err != nil {
		return "", ""
	}
	if ptr == nil || size < uint32(unsafe.Sizeof(vsFixedFileInfo{})) {
		return "", ""
	}

	ffi := (*vsFixedFileInfo)(ptr)
	if ffi.Signature != fixedFileInfoSignature {
		return "", ""
	}
	return formatFixedVersion(ffi.FileVersionMS, ffi.FileVersionLS),
		formatFixedVersion(ffi.ProductVersionMS, ffi.ProductVersionLS)
}

// translations lists the language/code-page pairs the binary declares.
func translations(buf []byte) []translation {
	var (
		ptr  unsafe.Pointer
		size uint32
	)
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\VarFileInfo\Translation`,
		unsafe.Pointer(&ptr), &size); err != nil || ptr == nil {
		// No translation block. 040904B0 -- US English, Unicode -- is the
		// overwhelmingly common case and is worth one attempt rather than
		// giving up on the string table entirely.
		return []translation{{0x0409, 0x04B0}}
	}

	n := int(size) / int(unsafe.Sizeof(translation{}))
	if n <= 0 {
		return []translation{{0x0409, 0x04B0}}
	}
	return unsafe.Slice((*translation)(ptr), n)
}

// stringValue reads one entry from the string table.
func stringValue(buf []byte, subBlock string) string {
	var (
		ptr  unsafe.Pointer
		size uint32
	)
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), subBlock,
		unsafe.Pointer(&ptr), &size); err != nil || ptr == nil || size == 0 {
		return ""
	}
	// size counts UTF-16 code units including the terminator.
	return windows.UTF16ToString(unsafe.Slice((*uint16)(ptr), size))
}
