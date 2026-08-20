package usn

import "testing"

// A small NTFS-shaped tree:
//
//	C:\                     (5, the root)
//	  Windows               (10)
//	    System32            (11)
//	  Program Files         (20)
//	    NVIDIA Corporation  (21)
var testDirs = map[uint64]dirEntry{
	10: {name: "Windows", parent: rootFileRef},
	11: {name: "System32", parent: 10},
	20: {name: "Program Files", parent: rootFileRef},
	21: {name: "NVIDIA Corporation", parent: 20},
}

func TestResolvePath(t *testing.T) {
	cases := []struct {
		name      string
		parentRef uint64
		file      string
		want      string
	}{
		{"directly in the root", rootFileRef, "pagefile.sys", `C:\pagefile.sys`},
		{"one level down", 10, "explorer.exe", `C:\Windows\explorer.exe`},
		{"two levels down", 11, "kernel32.dll", `C:\Windows\System32\kernel32.dll`},
		{"through a name with a space", 20, "setup.exe", `C:\Program Files\setup.exe`},
		{"two names with spaces", 21, "nvcuda.dll", `C:\Program Files\NVIDIA Corporation\nvcuda.dll`},
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
		11: {name: "System32", parent: 10}, // parent 10 was never seen
	}
	got, ok := resolvePath("C:", orphaned, 11, "kernel32.dll")
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
			10: {name: "a", parent: 11},
			11: {name: "b", parent: 10},
		}
		if _, ok := resolvePath("C:", cyclic, 10, "f.dll"); ok {
			t.Fatal("resolved a path through a cycle")
		}
	})

	t.Run("self-parent", func(t *testing.T) {
		selfish := map[uint64]dirEntry{12: {name: "loop", parent: 12}}
		if _, ok := resolvePath("C:", selfish, 12, "f.dll"); ok {
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
			deep[base+i] = dirEntry{name: "d", parent: base + i + 1}
		}
		if _, ok := resolvePath("C:", deep, base, "f.dll"); ok {
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
	dirs := map[uint64]dirEntry{10: {name: "Windows", parent: rootFileRef}}
	candidates := []candidate{
		{name: "explorer.exe", fileRef: 100, parentRef: 10},
		{name: "orphan.dll", fileRef: 101, parentRef: 999}, // parent never seen
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
