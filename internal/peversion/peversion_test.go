package peversion

import "testing"

func TestFormatFixedVersion(t *testing.T) {
	cases := []struct {
		ms, ls uint32
		want   string
	}{
		{0x000A0000, 0x4A610000, "10.0.19041.0"},
		{0x00010002, 0x00030004, "1.2.3.4"},
		{0, 0, "0.0.0.0"},
		{0xFFFFFFFF, 0xFFFFFFFF, "65535.65535.65535.65535"},
		// The transposition that produces a plausible-looking wrong answer.
		{0x0000000A, 0x00000001, "0.10.0.1"},
	}
	for _, tc := range cases {
		if got := formatFixedVersion(tc.ms, tc.ls); got != tc.want {
			t.Errorf("formatFixedVersion(%#08x, %#08x) = %q, want %q", tc.ms, tc.ls, got, tc.want)
		}
	}
}

func TestInfoEmpty(t *testing.T) {
	if !(Info{}).Empty() {
		t.Error("a zero Info should be empty")
	}
	for _, i := range []Info{
		{ProductName: "x"}, {CompanyName: "x"}, {FileVersion: "x"},
		{FixedFileVersion: "1.0.0.0"}, {OriginalFilename: "x"},
	} {
		if i.Empty() {
			t.Errorf("%+v should not be empty", i)
		}
	}
	// LegalCopyright alone is not useful information about what a binary is.
	if !(Info{LegalCopyright: "(c) someone"}).Empty() {
		t.Error("copyright alone should count as empty")
	}
}
