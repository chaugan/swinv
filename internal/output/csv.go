package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/chaugan/swinv/internal/model"
)

// multiValueSep separates the elements of the multi-valued CSV columns
// (cpes, licenses, locations) inside their single field.
const multiValueSep = ";"

// csvColumns is the CSV header, in the exact order required by the spec. Host
// identity is repeated on every row so a file stays useful standalone when
// rows are concatenated across machines.
var csvColumns = []string{
	"hostname",
	"machine_id",
	"os_id",
	"os_version_id",
	"architecture",
	"scanned_at",
	"name",
	"version",
	"type",
	"language",
	"purl",
	"cpes",
	"licenses",
	"locations",
	"found_by",
	// Appended in schema 1.1. Always present so the column shape never varies
	// with flags, which is what lets CSVs be concatenated across machines and
	// runs. Empty unless --hash / --since were used.
	"sha256",
	"change",
}

// CSVColumns returns a copy of the CSV header row, in order. It exists so
// callers and tests can assert the column contract without duplicating it.
func CSVColumns() []string {
	return append([]string(nil), csvColumns...)
}

// WriteCSV writes the report as RFC 4180 CSV: one row per component, UTF-8
// with no byte-order mark, "\n" line endings, and the header row always
// present — a report with no components still emits the header.
//
// Values containing a comma, a double quote, or a newline are quoted and
// escaped by encoding/csv. The cpes, licenses, and locations columns are
// multi-valued and are joined with ";" inside their single field. scanned_at
// is ScanMeta.StartedAt rendered as RFC 3339 in UTC.
//
// It does not close w.
func WriteCSV(w io.Writer, r *model.Report) error {
	if r == nil {
		return ErrNilReport
	}

	cw := csv.NewWriter(w)
	// RFC 4180 permits CRLF, but "\n" is what every Unix consumer of these
	// files expects and it keeps output byte-stable across platforms.
	cw.UseCRLF = false

	if err := cw.Write(csvColumns); err != nil {
		return fmt.Errorf("output: writing csv header: %w", err)
	}

	scannedAt := formatScannedAt(r.Scan.StartedAt)
	record := make([]string, len(csvColumns))
	for _, c := range r.Components {
		record[0] = r.Host.Hostname
		record[1] = r.Host.MachineID
		record[2] = r.Host.OSID
		record[3] = r.Host.OSVersionID
		record[4] = r.Host.Architecture
		record[5] = scannedAt
		record[6] = c.Name
		record[7] = c.Version
		record[8] = c.Type
		record[9] = c.Language
		record[10] = c.PURL
		record[11] = strings.Join(c.CPEs, multiValueSep)
		record[12] = strings.Join(c.Licenses, multiValueSep)
		record[13] = strings.Join(c.Locations, multiValueSep)
		record[14] = c.FoundBy
		record[15] = c.SHA256
		record[16] = c.Change
		if err := cw.Write(record); err != nil {
			return fmt.Errorf("output: writing csv row for %q: %w", c.Name, err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("output: flushing csv: %w", err)
	}
	return nil
}

// formatScannedAt renders a scan start time the way every format spells it:
// RFC 3339, normalised to UTC so files from machines in different time zones
// sort and compare directly.
func formatScannedAt(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
