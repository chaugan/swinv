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
	Version   string   `json:"version"`
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
	Attributes map[string]string `json:"attributes,omitempty"`
}

// WriteNDJSON writes one JSON object per component, one per line, with no
// indentation and a trailing newline after every record. A report with no
// components produces no output at all, which is the correct empty document
// for this format.
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
