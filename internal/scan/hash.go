package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/chrzz/swinv/internal/model"
)

// maxHashFileSize caps how large a file swinv will digest. Package databases
// and shared objects are small; a multi-gigabyte disk image reachable from a
// component's location list is not worth the read, and hashing it would make
// the scan duration unpredictable.
const maxHashFileSize = 512 << 20 // 512 MiB

// HashComponents fills in Component.SHA256 for every component whose primary
// location is a regular file, reading each file at most once.
//
// This is opt-in (--hash) because it is a large amount of extra I/O: it reads
// the full contents of every distinct file backing a component, where the rest
// of the scan mostly reads package metadata. It is useful for change detection
// and integrity checking, which is exactly what makes it worth the cost when
// you actually want it.
//
// root is the scan root; component locations are absolute system paths with
// the root stripped, so they are rejoined here. Unreadable or oversized files
// are skipped silently: a missing digest is not an error, and a scan must not
// fail because one file disappeared mid-run.
//
// Digests are cached per path, so a file backing several components is read
// once. The work is spread over parallelism workers, defaulting to NumCPU.
func HashComponents(ctx context.Context, root string, parallelism int, components []model.Component) (hashed int, warnings []string) {
	if len(components) == 0 {
		return 0, nil
	}
	if parallelism <= 0 {
		parallelism = runtime.NumCPU()
	}

	// Count how many components each candidate file backs. A path shared by
	// several components is a package database (/var/lib/dpkg/status and
	// friends), not the component's own content: digesting it would give every
	// deb on the machine the same hash, and would make all of them look
	// changed whenever any single package changed. That is the opposite of
	// useful for change detection, so shared evidence files are skipped and
	// only files that uniquely back one component are hashed.
	refs := make(map[string]int)
	for i := range components {
		if p := primaryLocation(components[i]); p != "" {
			refs[p]++
		}
	}
	paths := make(map[string]struct{}, len(refs))
	for p, n := range refs {
		if n == 1 {
			paths[p] = struct{}{}
		}
	}
	if shared := len(refs) - len(paths); shared > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"%d shared evidence file(s) such as package databases were not hashed; "+
				"a digest of a file backing many components identifies none of them",
			shared))
	}
	if len(paths) == 0 {
		// Everything was a shared evidence file. The warning above still stands.
		return 0, warnings
	}

	type result struct {
		path   string
		digest string
	}

	work := make(chan string)
	results := make(chan result)

	var wg sync.WaitGroup
	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range work {
				if ctx.Err() != nil {
					return
				}
				digest, err := hashFile(joinRoot(root, p))
				if err != nil {
					continue
				}
				select {
				case results <- result{p, digest}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(work)
		for p := range paths {
			select {
			case work <- p:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	digests := make(map[string]string, len(paths))
	for r := range results {
		digests[r.path] = r.digest
	}

	for i := range components {
		p := primaryLocation(components[i])
		if p == "" {
			continue
		}
		if d, ok := digests[p]; ok {
			components[i].SHA256 = d
			hashed++
		}
	}

	if skipped := len(paths) - len(digests); skipped > 0 {
		// A cancelled or timed-out run leaves digests missing for a completely
		// different reason; reporting those as "unreadable" would send the
		// operator looking for a permissions problem that does not exist.
		if err := ctx.Err(); err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"hashing stopped early after %d of %d component file(s): %v",
				len(digests), len(paths), err))
			return hashed, warnings
		}
		warnings = append(warnings, fmt.Sprintf(
			"%d of %d component file(s) could not be hashed (unreadable, too large, or removed mid-scan)",
			skipped, len(paths)))
	}
	return hashed, warnings
}

// primaryLocation is the file a component's digest is taken from: the first of
// its sorted locations. Locations are already sorted by model.Normalize, so
// this is stable between runs, which matters because the digest ends up in
// output that is meant to be diffable.
func primaryLocation(c model.Component) string {
	if len(c.Locations) == 0 {
		return ""
	}
	return c.Locations[0]
}

// joinRoot maps an absolute system path back onto the scan root.
func joinRoot(root, p string) string {
	if root == "" || root == "/" {
		return p
	}
	return filepath.Join(root, p)
}

// hashFile returns the hex SHA-256 of a regular file.
func hashFile(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	// Only regular files: hashing a device node or a fifo would block or read
	// something that is not content at all.
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file")
	}
	if fi.Size() > maxHashFileSize {
		return "", fmt.Errorf("file is larger than the %d byte hashing limit", int64(maxHashFileSize))
	}

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxHashFileSize)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
