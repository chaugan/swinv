package usn

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// buildV2 assembles a USN_RECORD_V2 exactly as the kernel lays it out. Having
// the test build the bytes rather than reusing the parser's constants means a
// mistake in those constants shows up as a failure instead of cancelling out.
func buildV2(fileRef, parentRef uint64, attrs uint32, name string) []byte {
	nameUTF16 := utf16.Encode([]rune(name))
	nameBytes := make([]byte, len(nameUTF16)*2)
	for i, u := range nameUTF16 {
		binary.LittleEndian.PutUint16(nameBytes[i*2:], u)
	}

	const header = 60
	// Records are padded to an eight-byte boundary on disk.
	length := header + len(nameBytes)
	if pad := length % 8; pad != 0 {
		length += 8 - pad
	}

	rec := make([]byte, length)
	binary.LittleEndian.PutUint32(rec[0:], uint32(length))
	binary.LittleEndian.PutUint16(rec[4:], 2) // MajorVersion
	binary.LittleEndian.PutUint16(rec[6:], 0) // MinorVersion
	binary.LittleEndian.PutUint64(rec[8:], fileRef)
	binary.LittleEndian.PutUint64(rec[16:], parentRef)
	binary.LittleEndian.PutUint32(rec[52:], attrs)
	binary.LittleEndian.PutUint16(rec[56:], uint16(len(nameBytes)))
	binary.LittleEndian.PutUint16(rec[58:], header)
	copy(rec[header:], nameBytes)
	return rec
}

func buildV3(fileRef, parentRef uint64, attrs uint32, name string) []byte {
	nameUTF16 := utf16.Encode([]rune(name))
	nameBytes := make([]byte, len(nameUTF16)*2)
	for i, u := range nameUTF16 {
		binary.LittleEndian.PutUint16(nameBytes[i*2:], u)
	}

	const header = 76
	length := header + len(nameBytes)
	if pad := length % 8; pad != 0 {
		length += 8 - pad
	}

	rec := make([]byte, length)
	binary.LittleEndian.PutUint32(rec[0:], uint32(length))
	binary.LittleEndian.PutUint16(rec[4:], 3)
	// FILE_ID_128 is little-endian; the low 64 bits come first.
	binary.LittleEndian.PutUint64(rec[8:], fileRef)
	binary.LittleEndian.PutUint64(rec[24:], parentRef)
	binary.LittleEndian.PutUint32(rec[68:], attrs)
	binary.LittleEndian.PutUint16(rec[72:], uint16(len(nameBytes)))
	binary.LittleEndian.PutUint16(rec[74:], header)
	copy(rec[header:], nameBytes)
	return rec
}

func collect(t *testing.T, buf []byte) []rawRecord {
	t.Helper()
	var got []rawRecord
	if err := parseRecords(buf, func(r rawRecord) error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatalf("parseRecords: %v", err)
	}
	return got
}

func TestParseV2Records(t *testing.T) {
	buf := append(buildV2(100, 5, 0, "kernel32.dll"),
		buildV2(101, 100, attrDirectory, "System32")...)

	got := collect(t, buf)
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if got[0].Name != "kernel32.dll" || got[0].FileRef != 100 || got[0].ParentRef != 5 {
		t.Errorf("first record = %+v", got[0])
	}
	if got[1].Name != "System32" || got[1].Attributes&attrDirectory == 0 {
		t.Errorf("second record = %+v, want a directory named System32", got[1])
	}
}

func TestParseV3Records(t *testing.T) {
	got := collect(t, buildV3(0xDEADBEEF, 5, 0, "refs-style.dll"))
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	// V3 shifts every field after the reference by 16 bytes. Reading it with
	// V2 offsets would yield a plausible-looking but wrong parent, which is
	// the failure this asserts against.
	if got[0].Name != "refs-style.dll" || got[0].FileRef != 0xDEADBEEF || got[0].ParentRef != 5 {
		t.Errorf("record = %+v", got[0])
	}
}

func TestParseMixedVersions(t *testing.T) {
	buf := append(buildV2(1, 5, 0, "a.exe"), buildV3(2, 5, 0, "b.exe")...)
	got := collect(t, buf)
	if len(got) != 2 || got[0].Name != "a.exe" || got[1].Name != "b.exe" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseNonASCIIName(t *testing.T) {
	// A real name from a localised install, plus an emoji, because NTFS
	// permits any UTF-16 sequence and an inventory that drops such files is
	// wrong in a way nobody notices until it matters.
	for _, name := range []string{"Größe.dll", "日本語.exe", "emoji-🎁.dll"} {
		got := collect(t, buildV2(1, 5, 0, name))
		if len(got) != 1 || got[0].Name != name {
			t.Errorf("round-trip of %q gave %+v", name, got)
		}
	}
}

func TestParseUnpairedSurrogateDoesNotFail(t *testing.T) {
	// An unpaired surrogate is a legal NTFS name and an illegal UTF-16
	// sequence. It must degrade to U+FFFD, not abort the enumeration: one
	// weird filename should never cost the rest of the volume.
	rec := buildV2(1, 5, 0, "ok")
	nameOff := int(binary.LittleEndian.Uint16(rec[58:]))
	binary.LittleEndian.PutUint16(rec[nameOff:], 0xD800) // high surrogate, unpaired

	got := collect(t, rec)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if !strings.ContainsRune(got[0].Name, '�') {
		t.Errorf("name = %q, want the replacement character", got[0].Name)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	valid := buildV2(1, 5, 0, "good.dll")

	corrupt := func(fn func([]byte)) []byte {
		b := append([]byte(nil), valid...)
		fn(b)
		return b
	}

	cases := map[string][]byte{
		"truncated below a header": valid[:40],
		"zero record length":       corrupt(func(b []byte) { binary.LittleEndian.PutUint32(b[0:], 0) }),
		"length past the buffer":   corrupt(func(b []byte) { binary.LittleEndian.PutUint32(b[0:], 4096) }),
		"unknown version":          corrupt(func(b []byte) { binary.LittleEndian.PutUint16(b[4:], 9) }),
		"name overlapping header":  corrupt(func(b []byte) { binary.LittleEndian.PutUint16(b[58:], 8) }),
		"odd name length":          corrupt(func(b []byte) { binary.LittleEndian.PutUint16(b[56:], 7) }),
		"name past the record":     corrupt(func(b []byte) { binary.LittleEndian.PutUint16(b[56:], 4096) }),
	}

	for name, buf := range cases {
		t.Run(name, func(t *testing.T) {
			err := parseRecords(buf, func(rawRecord) error { return nil })
			if err == nil {
				t.Fatal("want an error, got nil: a malformed buffer must be diagnosable, not silently wrong")
			}
		})
	}
}

func TestParseEmptyBuffer(t *testing.T) {
	if err := parseRecords(nil, func(rawRecord) error {
		t.Fatal("callback ran on an empty buffer")
		return nil
	}); err != nil {
		t.Fatalf("empty buffer should be a no-op, got %v", err)
	}
}
