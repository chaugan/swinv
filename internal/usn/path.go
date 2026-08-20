package usn

import (
	"fmt"
	"strings"
)

const (
	// rootFileIndex is the MFT record index of an NTFS volume root directory.
	// It is fixed by the on-disk format, and is where every path
	// reconstruction terminates.
	rootFileIndex = 5

	// fileRefMask extracts the record index from a file reference number.
	//
	// A reference is not a bare index: the low 48 bits are the MFT record
	// number and the high 16 are a sequence number, incremented each time the
	// record is reused for a different file. The root directory's full
	// reference is therefore 0x0005000000000005, not 5.
	//
	// Comparing or keying on the full reference is the obvious mistake and it
	// fails silently -- on a real volume it left 100% of paths unresolved,
	// because no chain ever recognised the root. Every identity comparison
	// here masks first.
	fileRefMask = 0x0000FFFFFFFFFFFF

	// maxPathDepth guards path reconstruction against a parent cycle. NTFS
	// should not produce one, but the MFT is read live while the filesystem is
	// changing, and an inventory tool must not be capable of hanging on
	// unexpected input.
	maxPathDepth = 512
)

// This file carries no build tag on purpose. Path reconstruction is the most
// intricate logic in the package -- MFT order is not tree order, ancestors can
// vanish mid-enumeration, and a wrong answer here produces a plausible but
// incorrect path, which is the worst failure an inventory can have. Keeping it
// free of syscalls means it can be tested anywhere, including on the machine
// it is being written on.

// candidate is an entry held for path reconstruction, which can only happen
// once every directory record has been seen.
type candidate struct {
	name       string
	fileRef    uint64
	parentRef  uint64
	attributes uint32
}

// dirEntry is a directory held during enumeration so that its children can be
// given a path. Only the name and parent are needed; nothing else about a
// directory matters for reconstruction.
type dirEntry struct {
	name   string
	parent uint64
}

// mftIndex strips the sequence number from a file reference, leaving the MFT
// record index that identifies a file within a volume.
func mftIndex(ref uint64) uint64 { return ref & fileRefMask }

// resolvePath walks the parent chain to the volume root. A missing ancestor is
// reported rather than guessed at: the MFT is enumerated while the filesystem
// is live, so a directory can be deleted between its child's record being read
// and its own, and inventing a path for such a file would be worse than
// admitting the gap.
func resolvePath(volume string, dirs map[uint64]dirEntry, parentRef uint64, name string) (string, bool) {
	var parts []string
	ref := mftIndex(parentRef)

	for depth := 0; ref != rootFileIndex; depth++ {
		if depth >= maxPathDepth {
			return "", false
		}
		d, ok := dirs[ref]
		if !ok {
			return "", false
		}
		parts = append(parts, d.name)
		if mftIndex(d.parent) == ref {
			// Self-parent: the only legitimate case is the root, handled by
			// the loop condition. Anything else is a cycle.
			return "", false
		}
		ref = mftIndex(d.parent)
	}

	var b strings.Builder
	b.WriteString(volume)
	for i := len(parts) - 1; i >= 0; i-- {
		b.WriteByte('\\')
		b.WriteString(parts[i])
	}
	b.WriteByte('\\')
	b.WriteString(name)
	return b.String(), true
}

// normalizeVolume accepts "C:", "C:\" or "c:" and returns "C:".
func normalizeVolume(v string) (string, error) {
	v = strings.TrimSpace(v)
	v = strings.TrimRight(v, `\/`)
	if len(v) != 2 || v[1] != ':' {
		return "", fmt.Errorf("usn: %q is not a drive specification such as \"C:\"", v)
	}
	letter := v[0]
	if letter >= 'a' && letter <= 'z' {
		letter -= 'a' - 'A'
	}
	if letter < 'A' || letter > 'Z' {
		return "", fmt.Errorf("usn: %q is not a drive specification such as \"C:\"", v)
	}
	return string([]byte{letter, ':'}), nil
}

// buildResult turns candidates into entries with full paths. It runs after
// enumeration rather than during it because MFT order is not tree order: a
// file's record routinely arrives before its parent directory's.
func buildResult(volume string, dirs map[uint64]dirEntry, candidates []candidate, records int) *Result {
	res := &Result{
		Entries:     make([]Entry, 0, len(candidates)),
		Records:     records,
		Directories: len(dirs),
	}

	for _, c := range candidates {
		e := Entry{
			Name:       c.name,
			IsDir:      c.attributes&attrDirectory != 0,
			Attributes: c.attributes,
			FileRef:    c.fileRef,
			ParentRef:  c.parentRef,
		}
		if p, ok := resolvePath(volume, dirs, c.parentRef, c.name); ok {
			e.Path = p
		} else {
			res.Unresolved++
		}
		res.Entries = append(res.Entries, e)
	}
	return res
}
