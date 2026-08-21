package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// serviceCSVColumns is the header of the services sidecar file.
//
// It is a separate file rather than extra columns on the component CSV because
// the two answer different questions and have different cardinality: a
// component appears once, a service appears once per listening process, and
// most components are behind no service at all. Wedging them together would
// give every row of the inventory fourteen empty columns.
//
// The first six columns are the same host identity the component CSV repeats
// on every row, and for the same reason: a file stays meaningful when rows
// from many machines are concatenated.
var serviceCSVColumns = []string{
	"hostname",
	"machine_id",
	"os_id",
	"os_version_id",
	"architecture",
	"scanned_at",
	"endpoints",
	"pid",
	"executable",
	"command",
	"unit",
	"container",
	"user",
	"socket_activated",
	"components",
	"confidence",
	"evidence",
}

// ServiceCSVColumns returns a copy of the services CSV header row, in order,
// so callers and tests can assert the column contract without restating it.
func ServiceCSVColumns() []string {
	return append([]string(nil), serviceCSVColumns...)
}

// WriteServicesCSV writes the report's services as RFC 4180 CSV, one row per
// listening process, with the header row always present.
//
// The multi-valued columns -- endpoints, components, evidence -- are joined
// with ";" inside their single field, exactly as the component CSV joins cpes
// and locations.
//
// It does not close w.
func WriteServicesCSV(w io.Writer, r *model.Report) error {
	if r == nil {
		return ErrNilReport
	}

	cw := csv.NewWriter(w)
	cw.UseCRLF = false

	if err := cw.Write(serviceCSVColumns); err != nil {
		return fmt.Errorf("output: writing services csv header: %w", err)
	}

	scannedAt := formatScannedAt(r.Scan.StartedAt)
	record := make([]string, len(serviceCSVColumns))
	for _, s := range r.Services {
		record[0] = r.Host.Hostname
		record[1] = r.Host.MachineID
		record[2] = r.Host.OSID
		record[3] = r.Host.OSVersionID
		record[4] = r.Host.Architecture
		record[5] = scannedAt
		record[6] = strings.Join(s.Endpoints, multiValueSep)
		record[7] = ""
		if s.PID != 0 {
			record[7] = strconv.Itoa(s.PID)
		}
		record[8] = s.Executable
		record[9] = s.Command
		record[10] = s.Unit
		record[11] = s.Container
		record[12] = s.User
		record[13] = strconv.FormatBool(s.SocketActivated)
		record[14] = strings.Join(s.Components, multiValueSep)
		record[15] = string(s.Confidence)
		record[16] = strings.Join(s.Evidence, multiValueSep)
		if err := cw.Write(record); err != nil {
			return fmt.Errorf("output: writing services csv row for pid %d: %w", s.PID, err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("output: flushing services csv: %w", err)
	}
	return nil
}
