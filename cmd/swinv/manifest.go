package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/chaugan/swinv/internal/configsurface"
	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/service"
)

// newScanID mints the identifier for one run.
//
// A UUIDv4 from crypto/rand rather than hostname+timestamp: it is the
// idempotency key the server dedupes batches on, and two scans of the same
// host started in the same second -- a timer firing while a manual run is in
// flight -- must not collide into one. Collision there would not error; it
// would merge two inventories and reconcile cleanly against neither.
func newScanID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read on any supported platform only fails if the system
		// entropy source is gone, in which case nothing else here is
		// trustworthy either. Fall back to something unique-enough rather than
		// abort a scan over it, and make the value obviously degraded.
		return "scan-no-entropy-" + hex.EncodeToString(b[:8])
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// buildManifest fills in the self-describing part of the report: the scan id
// and what every source did.
//
// It must run against the full inventory, before --delta-only trims the
// component list, or the sources would report a fraction of what the machine
// actually has and the numbers an operator checks would be the wrong ones.
//
// It returns the sources that failed. A caller that ignores that return has
// reintroduced the whole problem.
func buildManifest(cfg *config, report *model.Report, services model.SourceStatus) []string {
	report.Scan.ScanID = newScanID()
	report.Scan.Profile = scanProfile(cfg)

	// Stamp each component with the manifest sources key it is counted
	// under, so a consumer joins component to source directly. The mapping
	// lives in sourceKey and nowhere else, which is the point: the key a
	// component carries and the key the manifest declares come from one
	// function and cannot drift.
	for i := range report.Components {
		report.Components[i].SourceKey = sourceKey(report.Components[i].FoundBy)
	}

	counts := componentsBySource(report.Components)
	results := probeSources(cfg.root, knownSourceProbes())
	sources := sourceStatuses(results, counts)

	// A cataloger expression is the operator deliberately not looking at some
	// ecosystems. Under one, "the database is readable and produced nothing"
	// stops being evidence of failure and becomes evidence of the flag, so the
	// verdict is downgraded rather than raised as an error the operator caused
	// on purpose.
	if cfg.catalogers != "" {
		for name, s := range sources {
			if s.Status == model.SourceError && s.Components == 0 {
				sources[name] = model.SourceStatus{
					Status: model.SourceSkipped,
					Reason: fmt.Sprintf("--catalogers %q did not select this source", cfg.catalogers),
				}
			}
		}
	}

	if services.Status != "" {
		// Listening sockets produce exposure records, not components, so this
		// entry always contributes zero and the source total still matches the
		// inventory. It is here for the reason the whole block exists: "no
		// ports are open" and "the sockets could not be read" are opposite
		// conclusions from an identical empty list.
		sources["services"] = services
	}
	if cfg.configScope == configsurface.ScopeOff {
		// Same contract as the other sources: "off by choice" must stay
		// distinguishable from "found nothing".
		sources["config-surface"] = model.SourceStatus{
			Status: model.SourceSkipped,
			Reason: "--config-scope off",
		}
	}
	if cfg.noContainers {
		// Only when skipped. When containers ARE inspected their packages join
		// the inventory under the container probes' own source names, and a
		// second entry here would double-count them.
		sources["containers"] = model.SourceStatus{
			Status: model.SourceSkipped,
			Reason: "--no-containers",
		}
	}

	report.Scan.Sources = sources

	// The count the receiver will check, checked here first. If these disagree
	// the manifest is already lying before it has left the machine, and the
	// only useful thing to do is say so where somebody is watching.
	if total := model.SourceComponentTotal(sources); total != len(report.Components) {
		report.Scan.AddWarning(fmt.Sprintf(
			"the scan's sources account for %d components but the inventory holds %d; "+
				"the manifest's per-source counts cannot be reconciled", total, len(report.Components)))
	}

	return model.FailedSources(sources)
}

// serviceSourceStatus turns the outcome of the listening-socket snapshot into
// a manifest entry.
//
// Every branch names a reason. "skipped" with no reason is the same dead end
// as no entry at all: it tells a reader that something did not happen and
// gives them nothing to do about it.
func serviceSourceStatus(cfg *config, snapshot *service.Result, err error) model.SourceStatus {
	switch {
	case cfg.noServices:
		return model.SourceStatus{Status: model.SourceSkipped, Reason: "--no-services"}
	case !service.Supported():
		return model.SourceStatus{Status: model.SourceSkipped,
			Reason: "listening sockets cannot be enumerated on this platform"}
	case !scanningLiveHost(cfg.root):
		return model.SourceStatus{Status: model.SourceSkipped,
			Reason: fmt.Sprintf("--root is %s, and listening sockets describe the running machine", cfg.root)}
	case err != nil:
		return model.SourceStatus{Status: model.SourceError,
			Reason: "could not enumerate listening sockets: " + err.Error()}
	case snapshot == nil:
		return model.SourceStatus{Status: model.SourceError,
			Reason: "the listening-socket snapshot returned nothing and gave no reason"}
	}
	return model.SourceStatus{Status: model.SourceOK}
}

// scanProfile records what this run was asked to collect, from the flags. A
// consumer reads it to compare only like scans with like: the fields that
// change how much is found are exactly the ones here.
func scanProfile(cfg *config) *model.ScanProfile {
	root := cfg.root
	if root == "" {
		root = "/"
	}
	return &model.ScanProfile{
		FullScan:      cfg.fullScan,
		Hash:          cfg.hash,
		ELFScope:      cfg.elfScope,
		ConfigScope:   cfg.configScope,
		NDJSONInclude: parseNDJSONInclude(cfg.ndjsonInclude),
		Containers:    !cfg.noContainers,
		Services:      !cfg.noServices,
		Root:          root,
	}
}
