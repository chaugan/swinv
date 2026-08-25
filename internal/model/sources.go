package model

import "sort"

// Source status values, as written into ScanMeta.Sources and into the NDJSON
// manifest record.
//
// The three are deliberately distinct facts. "Found nothing" and "could not
// look" produce identical component lists and opposite conclusions: a host
// with an unreadable dpkg database reports fifteen components and looks
// exactly like a healthy minimal machine. Anything downstream that cannot tell
// them apart will eventually report that host as clean.
const (
	// SourceOK means the source was read and its packages are in this scan.
	SourceOK = "ok"

	// SourceSkipped means the source is not present on this machine, or the
	// operator switched it off. Nothing was lost.
	SourceSkipped = "skipped"

	// SourceError means the source exists and should have been readable and
	// was not. Something WAS lost, and the count in this scan is wrong by an
	// unknown amount.
	SourceError = "error"
)

// SourceStatus records what one enumeration source did during a scan.
//
// Components is what this source contributed to this scan's inventory, not to
// the transmitted stream: see ScanMeta.Sources for why the two can differ.
// Reason is mandatory for anything other than SourceOK -- a status of
// "skipped" with no reason is the same dead end as no status at all.
type SourceStatus struct {
	Status     string `json:"status"`
	Components int    `json:"components"`
	Reason     string `json:"reason,omitempty"`
}

// SourceComponentTotal sums what every source claims to have contributed.
//
// The receiver checks this against the inventory size. They must agree: a
// component whose source is not accounted for is a component whose
// disappearance nobody would notice.
func SourceComponentTotal(sources map[string]SourceStatus) int {
	total := 0
	for _, s := range sources {
		total += s.Components
	}
	return total
}

// FailedSources names every source that errored, sorted, for a message an
// operator reads once and acts on.
func FailedSources(sources map[string]SourceStatus) []string {
	var out []string
	for name, s := range sources {
		if s.Status == SourceError {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
