package usn

import "testing"

// A small NTFS-shaped tree:
//
//	C:\                     (5, the root)
//	  Windows               (10)
//	    System32            (11)
//	  Program Files         (20)
//	    NVIDIA Corporation  (21)
//
// seq attaches a sequence number to a record index, producing a file reference
// of the shape NTFS actually stores. Real references always carry one, and
// tests that use bare indices pass while the code is wrong -- which is exactly
// what happened: a version of this file using bare indices was green on Linux
// while leaving 100% of paths unresolved on a real 1.3-million-record volume.
func seq(index, sequence uint64) uint64 { return sequence<<48 | index }

var rootRef = seq(rootFileIndex, 5)

// Keyed by record index, as the enumerator keys it; parents are stored as full
// references, as the kernel reports them.
var testDirs = map[uint64]dirEntry{
	10: {name: "Windows", parent: rootRef},
	11: {name: "System32", parent: seq(10, 3)},
	20: {name: "Program Files", parent: rootRef},
	21: {name: "NVIDIA Corporation", parent: seq(20, 9)},
}

func TestResolvePath(t *testing.T) {
	cases := []struct {
		name      string
		parentRef uint64
		file      string
		want      string
	}{
		{"directly in the root", rootRef, "pagefile.sys", `C:\pagefile.sys`},
		{"one level down", seq(10, 3), "explorer.exe", `C:\Windows\explorer.exe`},
		{"two levels down", seq(11, 1), "kernel32.dll", `C:\Windows\System32\kernel32.dll`},
		{"through a name with a space", seq(20, 9), "setup.exe", `C:\Program Files\setup.exe`},
		{"two names with spaces", seq(21, 2), "nvcuda.dll", `C:\Program Files\NVIDIA Corporation\nvcuda.dll`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolvePath("C:", testDirs, tc.parentRef, tc.file)
			if !ok {
				t.Fatalf("resolvePath returned not-ok for %s", tc.file)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A missing ancestor must be reported, never guessed at. Inventing a path
// would attach a real file to the wrong directory, which reads as a fact and
// is a lie -- strictly worse than an admitted gap.
func TestResolvePathMissingAncestorIsReportedNotGuessed(t *testing.T) {
	orphaned := map[uint64]dirEntry{
		11: {name: "System32", parent: seq(10, 3)}, // parent 10 was never seen
	}
	got, ok := resolvePath("C:", orphaned, seq(11, 1), "kernel32.dll")
	if ok {
		t.Fatalf("resolved to %q despite a missing ancestor", got)
	}
	if got != "" {
		t.Errorf("got %q, want an empty path alongside ok=false", got)
	}
}

// The MFT is read while the filesystem is live. A cycle should not occur, but
// an inventory tool must not be capable of hanging on unexpected input.
func TestResolvePathTerminatesOnCycles(t *testing.T) {
	t.Run("two-node cycle", func(t *testing.T) {
		cyclic := map[uint64]dirEntry{
			10: {name: "a", parent: seq(11, 2)},
			11: {name: "b", parent: seq(10, 4)},
		}
		if _, ok := resolvePath("C:", cyclic, seq(10, 4), "f.dll"); ok {
			t.Fatal("resolved a path through a cycle")
		}
	})

	t.Run("self-parent", func(t *testing.T) {
		selfish := map[uint64]dirEntry{12: {name: "loop", parent: seq(12, 7)}}
		if _, ok := resolvePath("C:", selfish, seq(12, 7), "f.dll"); ok {
			t.Fatal("resolved a path through a self-parenting directory")
		}
	})

	t.Run("chain longer than the depth guard", func(t *testing.T) {
		// Numbered from well above rootFileRef so the chain cannot terminate
		// by running through the root by accident, which is what an earlier
		// version of this test did -- it passed for the wrong reason and
		// exercised none of the guard.
		const base = 1000
		deep := map[uint64]dirEntry{}
		for i := uint64(0); i <= maxPathDepth+10; i++ {
			deep[base+i] = dirEntry{name: "d", parent: seq(base+i+1, 1)}
		}
		if _, ok := resolvePath("C:", deep, seq(base, 1), "f.dll"); ok {
			t.Fatal("resolved a path deeper than the guard allows")
		}
	})
}

func TestNormalizeVolume(t *testing.T) {
	good := map[string]string{
		"C:":    "C:",
		`C:\`:   "C:",
		"c:":    "C:",
		`d:\`:   "D:",
		"  E: ": "E:",
	}
	for in, want := range good {
		if got, err := normalizeVolume(in); err != nil || got != want {
			t.Errorf("normalizeVolume(%q) = %q, %v; want %q, nil", in, got, err, want)
		}
	}

	for _, bad := range []string{"", "C", "CC:", `\\server\share`, "1:", `C:\Windows`, "::"} {
		if got, err := normalizeVolume(bad); err == nil {
			t.Errorf("normalizeVolume(%q) = %q with no error; want a usage error", bad, got)
		}
	}
}

// buildResult is where filtering meets path reconstruction, and where an
// unresolved entry must still be reported rather than dropped: a file whose
// path is unknown is still evidence that the file exists.
func TestBuildResultCountsUnresolvedWithoutDropping(t *testing.T) {
	dirs := map[uint64]dirEntry{10: {name: "Windows", parent: rootRef}}
	candidates := []candidate{
		{name: "explorer.exe", fileRef: seq(100, 1), parentRef: seq(10, 3)},
		{name: "orphan.dll", fileRef: seq(101, 1), parentRef: seq(999, 1)}, // parent never seen
	}

	res := buildResult("C:", dirs, candidates, 42)

	if len(res.Entries) != 2 {
		t.Fatalf("got %d entries, want 2: an unresolved entry must not be dropped", len(res.Entries))
	}
	if res.Unresolved != 1 {
		t.Errorf("Unresolved = %d, want 1", res.Unresolved)
	}
	if res.Records != 42 || res.Directories != 1 {
		t.Errorf("Records = %d, Directories = %d; want 42 and 1", res.Records, res.Directories)
	}
	if res.Entries[0].Path != `C:\Windows\explorer.exe` {
		t.Errorf("resolved entry path = %q", res.Entries[0].Path)
	}
	if res.Entries[1].Path != "" {
		t.Errorf("unresolved entry path = %q, want empty", res.Entries[1].Path)
	}
	if res.Entries[1].Name != "orphan.dll" {
		t.Errorf("unresolved entry lost its name: %+v", res.Entries[1])
	}
}

// TestResolvePathIgnoresSequenceNumbers pins the bug that made every path on a
// real volume unresolvable. A file reference carries a sequence number in its
// high 16 bits; the root's full reference is 0x0005000000000005, not 5. Code
// that compares or keys on the full reference finds nothing and reports every
// entry as unresolved, silently and with no error anywhere.
//
// The same directory is looked up here through three different sequence
// numbers, which is what a live volume does as records are reused.
func TestResolvePathIgnoresSequenceNumbers(t *testing.T) {
	dirs := map[uint64]dirEntry{
		10: {name: "Windows", parent: seq(rootFileIndex, 5)},
	}

	for _, sequence := range []uint64{0, 1, 0xFFFF} {
		got, ok := resolvePath("C:", dirs, seq(10, sequence), "explorer.exe")
		if !ok {
			t.Fatalf("sequence %#x: not resolved", sequence)
		}
		if want := `C:\Windows\explorer.exe`; got != want {
			t.Errorf("sequence %#x: got %q, want %q", sequence, got, want)
		}
	}

	// And the root itself, whatever sequence it carries.
	for _, sequence := range []uint64{0, 5, 0xFFFF} {
		if got, ok := resolvePath("C:", dirs, seq(rootFileIndex, sequence), "pagefile.sys"); !ok ||
			got != `C:\pagefile.sys` {
			t.Errorf("root with sequence %#x: got %q, ok=%v", sequence, got, ok)
		}
	}
}

func TestMFTIndex(t *testing.T) {
	cases := map[uint64]uint64{
		0x0005000000000005: 5,
		0x0000000000000005: 5,
		0xFFFF00000000002A: 42,
		0x0001FFFFFFFFFFFF: 0xFFFFFFFFFFFF,
	}
	for ref, want := range cases {
		if got := mftIndex(ref); got != want {
			t.Errorf("mftIndex(%#016x) = %#x, want %#x", ref, got, want)
		}
	}
}

func TestParseVolumes(t *testing.T) {
	good := map[string][]string{
		"d:":          {"D:"},
		"d:,e:":       {"D:", "E:"},
		"D:, E: , f:": {"D:", "E:", "F:"},
		`d:\,e:\`:     {"D:", "E:"},
		"d:,d:,D:":    {"D:"},
		"e:,d:":       {"E:", "D:"},
		"d:,":         {"D:"},
		"c:":          {"C:"},
	}
	for spec, want := range good {
		got, err := ParseVolumes(spec)
		if err != nil {
			t.Errorf("ParseVolumes(%q): %v", spec, err)
			continue
		}
		if len(got) != len(want) {
			t.Errorf("ParseVolumes(%q) = %v, want %v", spec, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("ParseVolumes(%q) = %v, want %v", spec, got, want)
				break
			}
		}
	}

	// Empty means "use the default", not "scan nothing" -- a distinction the
	// caller has to be able to make.
	if got, err := ParseVolumes("   "); err != nil || got != nil {
		t.Errorf(`ParseVolumes("   ") = %v, %v; want nil, nil`, got, err)
	}

	for _, bad := range []string{",,", "d:,nonsense", `\\server\share`, "d:,c:\\Windows", "1:"} {
		if got, err := ParseVolumes(bad); err == nil {
			t.Errorf("ParseVolumes(%q) = %v with no error; want a usage error", bad, got)
		}
	}
}
