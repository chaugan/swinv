package elflink

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/chaugan/swinv/internal/pathnorm"
)

// binaryDirs are where executables and libraries live. /opt is included
// because it is exactly where unmanaged software goes, which is the software
// this exists to find; the price is walking whatever else was put there.
var binaryDirs = []string{
	"/usr/bin", "/usr/sbin", "/usr/libexec", "/usr/lib",
	"/usr/local/bin", "/usr/local/sbin", "/usr/local/lib",
	"/opt", "/srv",
}

// maxWalkFiles bounds the walk. The development host has 228k files under
// these directories and 5,845 of them are ELF; a machine an order of magnitude
// past the cap has a filesystem this feature should not be silently spending
// its time on, so the walk stops and says so instead.
const maxWalkFiles = 2_000_000

// FindELF walks the binary directories under root and returns every ELF
// object, as paths relative to root.
//
// Identification is by reading the four magic bytes, not by extension or
// permission bits: a library is not executable, and unmanaged binaries --
// again, the interesting ones -- follow no naming convention. Symlinked
// top-level dirs (the /usr merge, /bin -> /usr/bin) are followed once at the
// root level and deduplicated by the resolved path, so nothing is probed
// twice.
func FindELF(ctx context.Context, root string, excludes []string) (paths []string, truncated bool) {
	seen := map[string]bool{}
	var files int
	excluded := pathnorm.SubtreeExcludes(excludes)
	relFrom := strings.TrimSuffix(root, "/")

	for _, dir := range binaryDirs {
		real := filepath.Join(root, filepath.FromSlash(dir))
		// Follow a top-level symlink (the /usr merge) but record the target
		// so /bin and /usr/bin are not walked twice.
		resolved, err := filepath.EvalSymlinks(real)
		if err != nil {
			continue
		}
		if seen["dir:"+resolved] {
			continue
		}
		seen["dir:"+resolved] = true

		_ = filepath.Walk(resolved, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil
			}
			if ctx.Err() != nil {
				return filepath.SkipAll
			}
			if files >= maxWalkFiles {
				truncated = true
				return filepath.SkipAll
			}
			if excluded != nil {
				rel := strings.TrimPrefix(p, relFrom)
				if !strings.HasPrefix(rel, "/") {
					rel = "/" + rel
				}
				if excluded(rel) {
					if info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}
			if !info.Mode().IsRegular() || info.Size() < 64 {
				return nil
			}
			files++
			if !isELF(p) {
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return nil
			}
			paths = append(paths, "/"+filepath.ToSlash(rel))
			return nil
		})
	}
	sort.Strings(paths)
	return paths, truncated
}

// isELF reads exactly four bytes. Cheaper than elf.Open for the 97% of files
// that are not ELF, which is what makes walking a quarter-million files
// tolerable.
func isELF(p string) bool {
	f, err := os.Open(p) // #nosec G304 -- paths come from walking fixed directories
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return false
	}
	return magic == [4]byte{0x7f, 'E', 'L', 'F'}
}

// ProbeAll probes every path, returning links per executable plus the union of
// resolved library paths for an ownership probe.
//
// Shared-library resolution results are cached across binaries -- 5,845 ELF
// objects on the development host resolve to a few hundred distinct libraries,
// and re-stating the search dirs for each would multiply the stat calls by
// the population.
func ProbeAll(ctx context.Context, root string, paths []string, symbols bool) (map[string][]Link, []string) {
	out := make(map[string][]Link, len(paths))
	libSet := map[string]bool{}
	for _, p := range paths {
		if ctx.Err() != nil {
			break
		}
		links, err := Probe(p, Options{Root: root, Symbols: symbols})
		if err != nil || len(links) == 0 {
			continue
		}
		out[p] = links
		for _, l := range links {
			if l.Path != "" {
				libSet[l.Path] = true
			}
		}
	}
	libs := make([]string, 0, len(libSet))
	for l := range libSet {
		libs = append(libs, l)
	}
	sort.Strings(libs)
	return out, libs
}
