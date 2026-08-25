package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// A source is one place installed software is enumerated from: a package
// database, a registry hive, a container runtime, a filesystem walk.
//
// swinv has always known which sources it read and has never said so. That is
// the whole of the incident this exists to prevent: a host whose collector saw
// 3,993 components arrived as 15, and every layer -- shipper, indexer, matcher,
// dashboard -- reported success, because a small valid inventory and a healthy
// minimal machine produce identical documents. Naming the sources and their
// status makes the two distinguishable in the first record of the stream.

// sourceProbe is a package database swinv can check for directly, before and
// independently of whether any cataloger produced anything from it.
//
// The check is what separates "this machine has no rpmdb" from "this machine
// has an rpmdb and we could not read it". A cataloger reports zero components
// for both.
type sourceProbe struct {
	// Name is the key this source gets in the manifest. It must match the key
	// derived from the cataloger's own name in sourceKey, or one source would
	// appear twice under two spellings and the counts would double.
	Name string

	// What names the thing in a sentence an operator reads: "dpkg package
	// database".
	What string

	// Paths are candidate locations relative to the scan root, in preference
	// order. The first that exists is the one reported on.
	Paths []string

	// Dir marks evidence that is a directory of files (an rpmdb) rather than a
	// single file (dpkg's status).
	Dir bool
}

// probeResult is what one probe found on disk. It carries no judgement: the
// verdict needs the component count too, which the probe cannot see.
type probeResult struct {
	probe   sourceProbe
	path    string // the candidate that existed, empty when none did
	present bool
	empty   bool  // present, readable, and containing nothing
	err     error // present but unreadable
}

// probeSources checks each known package database under root.
//
// Errors other than "does not exist" are kept rather than swallowed. A
// permission error on /var/lib/dpkg/status is the single most likely cause of
// a scan that succeeds and reports almost nothing, and it is invisible in the
// component list by construction.
func probeSources(root string, probes []sourceProbe) []probeResult {
	if root == "" {
		root = "/"
	}
	out := make([]probeResult, 0, len(probes))
	for _, p := range probes {
		out = append(out, probeOne(root, p))
	}
	return out
}

func probeOne(root string, p sourceProbe) probeResult {
	res := probeResult{probe: p}
	for _, rel := range p.Paths {
		full := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Stat(full)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			// A stat that fails for any other reason -- most often a
			// permission error on a parent directory -- means the path may
			// well be there and unreadable. Reporting "not present" would be
			// a guess, and the wrong one is silent.
			res.path, res.present, res.err = full, true, err
			return res
		}
		res.path, res.present = full, true

		if p.Dir {
			entries, err := os.ReadDir(full)
			if err != nil {
				res.err = err
				return res
			}
			res.empty = len(entries) == 0
			return res
		}

		// Open rather than trust the mode bits: the mode says what the owner
		// intended, opening says what this process can actually do, and those
		// differ under SELinux, AppArmor, and any bind mount marked read-only
		// at a layer stat cannot see.
		f, err := os.Open(full) // #nosec G304 -- path is a fixed table entry joined to the operator's --root
		if err != nil {
			res.err = err
			return res
		}
		_ = f.Close()
		res.empty = info.Size() == 0
		return res
	}
	return res
}

// catalogerSources maps the catalogers that read a probed database onto that
// probe's name, so the probe's verdict and the cataloger's count describe one
// source rather than two.
//
// Only the probed ones are listed. Everything else keeps its own name, which
// is why this table stays four lines long instead of growing with every Syft
// release: a cataloger nobody has mapped still appears, under its own name,
// with its real count.
var catalogerSources = map[string]string{
	"dpkg-db-cataloger": "dpkg",
	"rpm-db-cataloger":  "rpm",
	"apk-db-cataloger":  "apk",
	"portage-cataloger": "portage",
}

// sourceKey is the manifest key for a component's found_by value.
//
// A component with no found_by is reported as "unattributed" rather than
// dropped. It is a real thing that happened -- Syft returns packages with an
// empty creator for a few paths -- and a component nobody counts is exactly
// the kind of loss the counts exist to expose.
func sourceKey(foundBy string) string {
	foundBy = strings.TrimSpace(foundBy)
	if foundBy == "" {
		return "unattributed"
	}
	if k, ok := catalogerSources[foundBy]; ok {
		return k
	}
	return strings.TrimSuffix(foundBy, "-cataloger")
}

// componentsBySource counts what each source contributed to this inventory.
func componentsBySource(components []model.Component) map[string]int {
	counts := make(map[string]int, 8)
	for _, c := range components {
		counts[sourceKey(c.FoundBy)]++
	}
	return counts
}

// sourceStatuses turns probe results and component counts into the manifest's
// sources block.
//
// The verdict for a probed source is the interesting part, and it needs both
// halves. A dpkg database that is absent is a fact about the machine; one that
// is present, non-empty, readable and produced no packages is a fact about the
// scan, and the second is a failure however valid the file it wrote looks.
func sourceStatuses(results []probeResult, counts map[string]int) map[string]model.SourceStatus {
	sources := make(map[string]model.SourceStatus, len(counts)+len(results))

	// Everything that produced components, first. These need no probe: the
	// components are their own evidence.
	for name, n := range counts {
		sources[name] = model.SourceStatus{Status: model.SourceOK, Components: n}
	}

	for _, r := range results {
		n := counts[r.probe.Name]
		switch {
		case !r.present:
			sources[r.probe.Name] = model.SourceStatus{
				Status: model.SourceSkipped,
				Reason: fmt.Sprintf("no %s on this host", r.probe.What),
			}
		case r.err != nil:
			sources[r.probe.Name] = model.SourceStatus{
				Status:     model.SourceError,
				Components: n,
				Reason:     fmt.Sprintf("cannot read the %s at %s: %v", r.probe.What, r.path, r.err),
			}
		case r.empty:
			sources[r.probe.Name] = model.SourceStatus{
				Status: model.SourceSkipped,
				Reason: fmt.Sprintf("the %s at %s is empty", r.probe.What, r.path),
			}
		case n == 0:
			// Readable, not empty, and nothing came out of it. Whatever the
			// cause, this scan is missing an entire ecosystem and says so
			// here rather than leaving a plausible-looking short inventory.
			sources[r.probe.Name] = model.SourceStatus{
				Status: model.SourceError,
				Reason: fmt.Sprintf("the %s at %s is readable and not empty, "+
					"but enumeration returned no packages", r.probe.What, r.path),
			}
		default:
			sources[r.probe.Name] = model.SourceStatus{Status: model.SourceOK, Components: n}
		}
	}
	return sources
}
