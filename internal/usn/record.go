package usn

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// Record layout, from USN_RECORD_V2 and USN_RECORD_V3 in winioctl.h. The
// versions differ in one thing: V2 identifies files with a 64-bit MFT
// reference, V3 with a 128-bit FILE_ID_128, which shifts every field after it.
//
// The fields are read by offset rather than by casting the buffer to a Go
// struct. A struct with these types would be padded to a multiple of eight and
// so would not match the packed layout the kernel writes -- a V2 header is 60
// bytes, where Go would make the equivalent struct 64. Reading by offset also
// means a malformed buffer produces an error rather than reading past the end
// of an allocation.
const (
	offRecordLength = 0
	offMajorVersion = 4

	v2OffFileRef    = 8
	v2OffParentRef  = 16
	v2OffAttributes = 52
	v2OffNameLength = 56
	v2OffNameOffset = 58
	v2HeaderLen     = 60

	v3OffFileRef    = 8
	v3OffParentRef  = 24
	v3OffAttributes = 68
	v3OffNameLength = 72
	v3OffNameOffset = 74
	v3HeaderLen     = 76
)

// rawRecord is the part of an MFT record this package uses. Everything else --
// the USN itself, timestamps, change reasons, the security id -- describes
// *changes* to a file, and this is an inventory of what exists.
type rawRecord struct {
	FileRef    uint64
	ParentRef  uint64
	Attributes uint32
	Name       string
}

// parseRecords walks a DeviceIoControl output buffer and calls fn for each
// record it contains. The buffer must already have had the leading eight-byte
// next-reference cursor removed.
//
// Every field is bounds-checked. This parses data from the kernel, so hostile
// input is not the concern; truncation and version drift are, and both should
// produce a diagnosable error rather than a panic or silent corruption.
func parseRecords(buf []byte, fn func(rawRecord) error) error {
	for offset := 0; offset < len(buf); {
		if remaining := len(buf) - offset; remaining < v2HeaderLen {
			return fmt.Errorf("usn: truncated record at offset %d: %d bytes left, need at least %d",
				offset, remaining, v2HeaderLen)
		}

		length := int(binary.LittleEndian.Uint32(buf[offset+offRecordLength:]))
		if length == 0 {
			return fmt.Errorf("usn: zero-length record at offset %d, which would not terminate", offset)
		}
		if length < 0 || offset+length > len(buf) {
			return fmt.Errorf("usn: record at offset %d claims %d bytes, only %d remain",
				offset, length, len(buf)-offset)
		}

		rec := buf[offset : offset+length]
		parsed, err := parseOne(rec)
		if err != nil {
			return fmt.Errorf("usn: record at offset %d: %w", offset, err)
		}
		if err := fn(parsed); err != nil {
			return err
		}
		offset += length
	}
	return nil
}

func parseOne(rec []byte) (rawRecord, error) {
	var offFileRef, offParentRef, offAttrs, offNameLen, offNameOff, headerLen int

	switch major := binary.LittleEndian.Uint16(rec[offMajorVersion:]); major {
	case 2:
		offFileRef, offParentRef = v2OffFileRef, v2OffParentRef
		offAttrs, offNameLen, offNameOff = v2OffAttributes, v2OffNameLength, v2OffNameOffset
		headerLen = v2HeaderLen
	case 3:
		offFileRef, offParentRef = v3OffFileRef, v3OffParentRef
		offAttrs, offNameLen, offNameOff = v3OffAttributes, v3OffNameLength, v3OffNameOffset
		headerLen = v3HeaderLen
	default:
		// Better to stop than to guess at an unknown layout and emit files
		// with wrong parents, which would produce plausible but incorrect
		// paths -- the worst possible failure for an inventory.
		return rawRecord{}, fmt.Errorf("unsupported USN record version %d", major)
	}

	if len(rec) < headerLen {
		return rawRecord{}, fmt.Errorf("record is %d bytes, shorter than its %d-byte header", len(rec), headerLen)
	}

	nameLen := int(binary.LittleEndian.Uint16(rec[offNameLen:]))
	nameOff := int(binary.LittleEndian.Uint16(rec[offNameOff:]))
	if nameOff < headerLen {
		return rawRecord{}, fmt.Errorf("file name offset %d overlaps the %d-byte header", nameOff, headerLen)
	}
	if nameLen%2 != 0 {
		return rawRecord{}, fmt.Errorf("file name length %d is odd, but names are UTF-16", nameLen)
	}
	if nameOff+nameLen > len(rec) {
		return rawRecord{}, fmt.Errorf("file name runs to %d, past the %d-byte record", nameOff+nameLen, len(rec))
	}

	// A 128-bit reference is used by its low 64 bits. On NTFS the upper half
	// is zero; ReFS uses the full width, but ReFS has no MFT to enumerate and
	// is rejected before reaching here.
	return rawRecord{
		FileRef:    binary.LittleEndian.Uint64(rec[offFileRef:]),
		ParentRef:  binary.LittleEndian.Uint64(rec[offParentRef:]),
		Attributes: binary.LittleEndian.Uint32(rec[offAttrs:]),
		Name:       decodeUTF16(rec[nameOff : nameOff+nameLen]),
	}, nil
}

// decodeUTF16 converts a little-endian UTF-16 byte run to a Go string.
//
// Windows file names are UTF-16 and are not required to be well-formed: an
// unpaired surrogate is a legal NTFS name. utf16.Decode maps those to
// U+FFFD rather than failing, which is the right trade here -- a file with an
// odd name should still appear in an inventory.
func decodeUTF16(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(units))
}

// attrDirectory is FILE_ATTRIBUTE_DIRECTORY. It is defined here rather than
// taken from x/sys/windows so that the parser and its tests build and run on
// every platform, which is what lets the record layout be verified without a
// Windows machine.
const attrDirectory = 0x00000010
