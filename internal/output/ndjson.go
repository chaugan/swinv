package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/chaugan/swinv/internal/model"
)

// ndjsonLine is one newline-delimited JSON record: a single component, flattened
// together with the host identity and scan time so that each line stands on its
// own when files from many machines are concatenated and fed to a log shipper or
// a `jq`/COPY pipeline.
//
// The field names and their order mirror the CSV columns exactly. The
// multi-valued fields stay JSON arrays rather than ";"-joined strings, because
// unlike CSV the format can represent them losslessly.
type ndjsonLine struct {
	Hostname     string `json:"hostname"`
	MachineID    string `json:"machine_id,omitempty"`
	OSID         string `json:"os_id,omitempty"`
	OSVersionID  string `json:"os_version_id,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	ScannedAt    string `json:"scanned_at"`

	Name      string   `json:"name"`
	Version   string   `json:"version,omitempty"`
	Type      string   `json:"type"`
	Language  string   `json:"language,omitempty"`
	PURL      string   `json:"purl,omitempty"`
	CPEs      []string `json:"cpes,omitempty"`
	Licenses  []string `json:"licenses,omitempty"`
	Locations []string `json:"locations,omitempty"`
	FoundBy   string   `json:"found_by,omitempty"`
	SourceKey string   `json:"source_key,omitempty"`
	SHA256    string   `json:"sha256,omitempty"`
	Change    string   `json:"change,omitempty"`

	// Added in schema 1.2 and 1.3. This struct enumerates its fields rather
	// than embedding model.Component, which is what let both additions ship
	// present in JSON and CSV and silently absent here -- a consumer reading
	// NDJSON lost them without any error to notice. TestEveryFormatCarries-
	// EveryComponentField now compares the two.
	Vendor     string            `json:"vendor,omitempty"`
	Root       string            `json:"root,omitempty"`
	OwnedBy    string            `json:"owned_by,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// heartbeatLine is the one record a scan emits when nothing has changed.
//
// It exists because the component stream is the right shape for correctness
// and the wrong shape for volume: every scan restates the whole inventory, so
// that a package which disappears is genuinely gone rather than merely
// unmentioned. At five thousand hosts averaging fourteen thousand components
// scanned hourly that is well over a billion records a day, nearly all of them
// identical to the day before.
//
// The digest is opaque to whoever reads it. It is never recomputed and never
// compared against anything but the previous value stored for the same host,
// which is what allows the algorithm behind it to change: a host whose digest
// changes shape looks changed exactly once, sends a full list, and agrees with
// itself thereafter.
type heartbeatLine struct {
	RecordType string `json:"record_type"`

	Hostname    string `json:"hostname"`
	Digest      string `json:"digest"`
	NComponents int    `json:"n_components"`
	ScannedAt   string `json:"scanned_at"`

	// Optional identity, so a consumer's host record stays fed on a scan that
	// sends no components at all.
	MachineID    string `json:"machine_id,omitempty"`
	OSID         string `json:"os_id,omitempty"`
	OSVersionID  string `json:"os_version_id,omitempty"`
	Architecture string `json:"architecture,omitempty"`

	// The Windows patch-level join key (issue #14): the build MSRC keys
	// remediations on, the release that decides end-of-service, and the
	// edition/installation type that separate client UBR ranges from server
	// ones. On the heartbeat because they are host identity - the one line
	// a consumer always gets, components suppressed or not. Empty on Linux.
	OSBuild            string `json:"os_build,omitempty"`
	OSDisplayVersion   string `json:"os_display_version,omitempty"`
	OSEdition          string `json:"os_edition,omitempty"`
	OSInstallationType string `json:"os_installation_type,omitempty"`

	// --- manifest, schema_version 2 --------------------------------------
	//
	// Everything below turns the heartbeat from "this host is alive" into
	// "this stream contains exactly the following". A receiver that stores
	// fewer component records than Counts says were sent has lost data, and
	// can say so in the same minute rather than after a day of narrowing down
	// which of eight layers dropped it. n_components above is kept exactly as
	// it was so a server that predates this parses the record unchanged.
	SchemaVersion int                           `json:"schema_version,omitempty"`
	ScanID        string                        `json:"scan_id,omitempty"`
	SwinvVersion  string                        `json:"swinv_version,omitempty"`
	Counts        map[string]int                `json:"counts,omitempty"`
	Sources       map[string]model.SourceStatus `json:"sources,omitempty"`

	// ScanProfile is what the scan was asked to collect, so a consumer
	// compares two scans of a host only when they are comparable (#15).
	ScanProfile *model.ScanProfile `json:"scan_profile,omitempty"`
	DurationMS  int64              `json:"duration_ms,omitempty"`

	// InventoryUnchanged explains the one case where Counts["component"] and
	// NComponents legitimately disagree: --heartbeat suppressed the component
	// records because the digest matched the previous scan. Without this the
	// receiver has to choose between reconciling against a number that is
	// deliberately zero and reconciling against one that is deliberately not,
	// and either choice reports a false discrepancy on every unchanged scan.
	InventoryUnchanged bool `json:"inventory_unchanged,omitempty"`

	// InventoryComponents is the host's full component count regardless of
	// what this stream carries -- the same number as n_components, named for
	// what it measures rather than for what it used to mean.
	InventoryComponents int `json:"inventory_components,omitempty"`
}

// manifestSchemaVersion is the version of the heartbeat record's own shape.
//
// 1 was hostname/digest/n_components/scanned_at plus host identity. 2 adds
// scan_id, counts, sources and duration_ms. The field is absent in 1 and
// present in 2, so a receiver tells them apart without a heuristic.
const manifestSchemaVersion = 2

// WriteNDJSON writes one JSON object per component, one per line, with no
// indentation and a trailing newline after every record. A report with no
// components produces no output at all, which is the correct empty document
// for this format.
//
// With --heartbeat, a single heartbeat record precedes the components, and the
// components are omitted entirely when the inventory has not changed since the
// last scan. The heartbeat carries "record_type": "heartbeat"; a record
// without that field is a component, which is what every line was before this
// existed and what every existing consumer already assumes.
//
// Deltas are deliberately not an option here. A delta cannot express a
// removal, and "this package is no longer installed" is the fact that decides
// whether a vulnerability is fixed or merely unreported. Sending the full list
// on change keeps that property while removing the volume.
//
// Each line repeats the host identity and the scan time alongside the
// component fields, using the same snake_case names as the CSV columns, so a
// single line is self-describing.
//
// It does not close w.
func WriteNDJSON(w io.Writer, r *model.Report) error {
	if r == nil {
		return ErrNilReport
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	scannedAt := formatScannedAt(r.Scan.StartedAt)

	// The manifest states the counts before a single record is written, so it
	// has to be able to predict them exactly. Everything below then counts
	// what it really wrote and the two are compared at the end: a writer that
	// declares 3,993 components and emits 15 must fail here rather than
	// produce a stream that looks healthy to everything downstream.
	planned := ndjsonCounts(r)

	if r.Scan.InventoryDigest != "" {
		if err := enc.Encode(manifestRecord(r, scannedAt, planned)); err != nil {
			return fmt.Errorf("output: writing ndjson heartbeat: %w", err)
		}
		if r.Scan.InventoryUnchanged {
			// The heartbeat replaces the *components*, which are the volume.
			// Exposure and container records are a few dozen per scan and say
			// what is listening right now, which is exactly the thing that can
			// change while the installed software does not -- a port opened,
			// a container started. Suppressing them would make the heartbeat
			// hide the fastest-moving facts in the report.
			written, err := writeExtraRecords(enc, r, scannedAt)
			if err != nil {
				return err
			}
			return reconcileNDJSON(planned, written)
		}
	}

	written, err := writeExtraRecords(enc, r, scannedAt)
	if err != nil {
		return err
	}

	for _, c := range r.Components {
		line := ndjsonLine{
			Hostname:     r.Host.Hostname,
			MachineID:    r.Host.MachineID,
			OSID:         r.Host.OSID,
			OSVersionID:  r.Host.OSVersionID,
			Architecture: r.Host.Architecture,
			ScannedAt:    scannedAt,
			Name:         c.Name,
			Version:      c.Version,
			Type:         c.Type,
			Language:     c.Language,
			PURL:         c.PURL,
			CPEs:         c.CPEs,
			Licenses:     c.Licenses,
			Locations:    c.Locations,
			FoundBy:      c.FoundBy,
			SourceKey:    c.SourceKey,
			SHA256:       c.SHA256,
			Vendor:       c.Vendor,
			Root:         c.Root,
			OwnedBy:      c.OwnedBy,
			Attributes:   c.Attributes,
			Change:       c.Change,
		}
		// Encode terminates every record with a newline, which is exactly the
		// NDJSON framing.
		if err := enc.Encode(line); err != nil {
			return fmt.Errorf("output: writing ndjson record for %q: %w", c.Name, err)
		}
		written[model.RecordComponent]++
	}
	return reconcileNDJSON(planned, written)
}

// ndjsonCounts predicts exactly how many records of each type this report will
// produce, in the same order of decisions the writer makes.
//
// It is deliberately a separate function from the writing loop rather than a
// tally kept alongside it: the manifest is line 1 and the records follow, so
// the count has to exist before the records do. reconcileNDJSON then closes
// the gap that separation opens.
func ndjsonCounts(r *model.Report) map[string]int {
	counts := map[string]int{
		model.RecordComponent: len(r.Components),
		model.RecordExposure:  0,
		model.RecordContainer: 0,
		model.RecordLink:      0,
		model.RecordConfig:    0,
	}
	if r.Scan.InventoryDigest != "" && r.Scan.InventoryUnchanged {
		counts[model.RecordComponent] = 0
	}
	if includes(r, recordExposure) {
		counts[model.RecordExposure] = countExposureLines(r)
	}
	if includes(r, recordContainer) {
		counts[model.RecordContainer] = len(r.Containers)
	}
	// The condition must mirror writeExtraRecords exactly: link records are
	// suppressed with the components on an unchanged heartbeat scan, and a
	// manifest that declared them anyway would report its own suppression as
	// data loss.
	if includes(r, recordLink) && !r.Scan.InventoryUnchanged {
		counts[model.RecordLink] = countLinkLines(r)
	}
	if includes(r, recordConfig) {
		counts[model.RecordConfig] = len(r.ConfigSurface)
	}
	return counts
}

// manifestRecord builds line 1: what this stream contains and where it came
// from.
func manifestRecord(r *model.Report, scannedAt string, counts map[string]int) heartbeatLine {
	return heartbeatLine{
		RecordType: recordHeartbeat,

		Hostname: r.Host.Hostname,
		Digest:   r.Scan.InventoryDigest,
		// Unchanged meaning, unchanged value: the host's full component count.
		// A pre-manifest server reads this field and nothing else, and it must
		// keep getting the same answer it always got.
		NComponents:  len(r.Components),
		ScannedAt:    scannedAt,
		MachineID:    r.Host.MachineID,
		OSID:         r.Host.OSID,
		OSVersionID:  r.Host.OSVersionID,
		Architecture: r.Host.Architecture,

		OSBuild:            r.Host.OSBuild,
		OSDisplayVersion:   r.Host.OSDisplayVersion,
		OSEdition:          r.Host.OSEdition,
		OSInstallationType: r.Host.OSInstallationType,

		SchemaVersion:       manifestSchemaVersion,
		ScanID:              r.Scan.ScanID,
		SwinvVersion:        r.Tool.Version,
		Counts:              counts,
		Sources:             r.Scan.Sources,
		ScanProfile:         r.Scan.Profile,
		DurationMS:          r.Scan.DurationMS,
		InventoryUnchanged:  r.Scan.InventoryUnchanged,
		InventoryComponents: len(r.Components),
	}
}

// reconcileNDJSON refuses to hand back a stream whose manifest disagrees with
// the records that followed it.
//
// This is the cheapest possible instance of the rule that every layer asserts
// expected against actual. It has never fired in practice, which is the point:
// the failure it guards is one where every layer reports success and the data
// is simply not there.
func reconcileNDJSON(planned, written map[string]int) error {
	for kind, want := range planned {
		if got := written[kind]; got != want {
			return fmt.Errorf(
				"output: ndjson manifest declared %d %s record(s) and %d were written; "+
					"the stream would have been silently wrong", want, kind, got)
		}
	}
	// The loop above visits planned keys only, so a record type the writer
	// emits but ndjsonCounts never heard of would pass it untouched - which
	// is the most likely future mistake: a new record type whose author
	// forgot the manifest.
	for kind, got := range written {
		if _, declared := planned[kind]; !declared && got != 0 {
			return fmt.Errorf(
				"output: %d %s record(s) were written that the manifest never declared; "+
					"a receiver losing all of them would reconcile clean", got, kind)
		}
	}
	return nil
}

// writeExtraRecords emits the non-component record types this run was asked
// for, and reports how many of each it actually wrote.
func writeExtraRecords(enc *json.Encoder, r *model.Report, scannedAt string) (map[string]int, error) {
	written := map[string]int{
		model.RecordComponent: 0,
		model.RecordExposure:  0,
		model.RecordContainer: 0,
		model.RecordLink:      0,
		model.RecordConfig:    0,
	}
	if includes(r, recordExposure) {
		for _, line := range exposureLines(r, scannedAt) {
			if err := enc.Encode(line); err != nil {
				return written, fmt.Errorf("output: writing ndjson exposure record: %w", err)
			}
			written[model.RecordExposure]++
		}
	}
	if includes(r, recordContainer) {
		for _, line := range containerLines(r, scannedAt) {
			if err := enc.Encode(line); err != nil {
				return written, fmt.Errorf("output: writing ndjson container record: %w", err)
			}
			written[model.RecordContainer]++
		}
	}
	// Links are derived from the installed software, which is exactly what
	// the heartbeat digest tracks -- a binary's DT_NEEDED changes when the
	// binary does. So unlike exposure and containers, which describe sockets
	// that move while software stands still, an unchanged scan emits no link
	// records: at --elf-scope all they are 36,000 rows on the development
	// host, and repeating them hourly would undo the heartbeat entirely.
	if includes(r, recordLink) && !r.Scan.InventoryUnchanged {
		for _, line := range linkLines(r, scannedAt) {
			if err := enc.Encode(line); err != nil {
				return written, fmt.Errorf("output: writing ndjson link record: %w", err)
			}
			written[model.RecordLink]++
		}
	}
	// Config records are emitted even on an unchanged heartbeat scan, like
	// exposure and containers: the inventory digest tracks installed
	// software, not configuration, so a new cron job on an unchanged host is
	// exactly the record suppression would hide.
	if includes(r, recordConfig) {
		for _, line := range configLines(r, scannedAt) {
			if err := enc.Encode(line); err != nil {
				return written, fmt.Errorf("output: writing ndjson config record: %w", err)
			}
			written[model.RecordConfig]++
		}
	}
	return written, nil
}

// includes reports whether a record type was asked for.
//
// Off by default, and deliberately: a consumer reading every line as a
// component predates all of this, and a record it does not recognise would
// arrive as a component with no name and no version.
func includes(r *model.Report, recordType string) bool {
	for _, want := range r.NDJSONInclude {
		if want == recordType {
			return true
		}
	}
	return false
}
