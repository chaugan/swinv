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
}

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

	if r.Scan.InventoryDigest != "" {
		if err := enc.Encode(heartbeatLine{
			RecordType:   "heartbeat",
			Hostname:     r.Host.Hostname,
			Digest:       r.Scan.InventoryDigest,
			NComponents:  len(r.Components),
			ScannedAt:    scannedAt,
			MachineID:    r.Host.MachineID,
			OSID:         r.Host.OSID,
			OSVersionID:  r.Host.OSVersionID,
			Architecture: r.Host.Architecture,
		}); err != nil {
			return fmt.Errorf("output: writing ndjson heartbeat: %w", err)
		}
		if r.Scan.InventoryUnchanged {
			// The heartbeat replaces the *components*, which are the volume.
			// Exposure and container records are a few dozen per scan and say
			// what is listening right now, which is exactly the thing that can
			// change while the installed software does not -- a port opened,
			// a container started. Suppressing them would make the heartbeat
			// hide the fastest-moving facts in the report.
			if err := writeExtraRecords(enc, r, scannedAt); err != nil {
				return err
			}
			return nil
		}
	}

	if err := writeExtraRecords(enc, r, scannedAt); err != nil {
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
	}
	return nil
}

// writeExtraRecords emits the non-component record types this run was asked
// for.
func writeExtraRecords(enc *json.Encoder, r *model.Report, scannedAt string) error {
	if includes(r, recordExposure) {
		for _, line := range exposureLines(r, scannedAt) {
			if err := enc.Encode(line); err != nil {
				return fmt.Errorf("output: writing ndjson exposure record: %w", err)
			}
		}
	}
	if includes(r, recordContainer) {
		for _, line := range containerLines(r, scannedAt) {
			if err := enc.Encode(line); err != nil {
				return fmt.Errorf("output: writing ndjson container record: %w", err)
			}
		}
	}
	return nil
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
