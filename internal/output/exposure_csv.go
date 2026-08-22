package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// exposureCSVColumns is the header of the exposure sidecar.
//
// One row per listening socket in the host network namespace, which is the
// unit of work for the system this file exists for: "is this port a problem"
// is a question about a port, and a process holding four sockets can be four
// different answers.
//
// Host identity repeats on every row for the same reason it does on the
// component CSV -- so rows from a fleet concatenate into one table -- and the
// scan-level qualifiers repeat too, because a denormalised consumer never sees
// the scan block and cannot otherwise tell a complete row from a partial one.
var exposureCSVColumns = []string{
	"hostname",
	"machine_id",
	"os_id",
	"os_version_id",
	"architecture",
	"scanned_at",
	"address",
	"port",
	"protocol",
	"family",
	"bind_scope",
	"wildcard_covers_ipv4",
	"pid",
	"executable",
	"unit",
	"user",
	"container",
	"backend_address",
	"backend_port",
	"backend_container",
	"backend_executable",
	"backend_via",
	"image_ref",
	"image_manifest_digest",
	"components",
	"confidence",
	"evidence",
	// Scan-level qualifiers, repeated per row. Without these a consumer
	// reading only this file cannot tell "nothing else is exposed" from
	// "nothing else could be seen".
	"ran_as_root",
	"firewall_examined",
	"exposure_blind_spots",
}

// ExposureCSVColumns returns a copy of the exposure CSV header, in order.
func ExposureCSVColumns() []string {
	return append([]string(nil), exposureCSVColumns...)
}

// WriteExposureCSV writes the report's exposure rows as RFC 4180 CSV, with the
// header always present.
//
// It does not close w.
func WriteExposureCSV(w io.Writer, r *model.Report) error {
	if r == nil {
		return ErrNilReport
	}

	cw := csv.NewWriter(w)
	cw.UseCRLF = false

	if err := cw.Write(exposureCSVColumns); err != nil {
		return fmt.Errorf("output: writing exposure csv header: %w", err)
	}

	var (
		scannedAt  = formatScannedAt(r.Scan.StartedAt)
		ranAsRoot  = strconv.FormatBool(r.Scan.RanAsRoot)
		firewall   = strconv.FormatBool(r.Scan.FirewallExamined)
		blindSpots = strings.Join(r.Scan.ExposureBlindSpots, multiValueSep)
	)
	record := make([]string, len(exposureCSVColumns))
	for _, e := range r.Exposure {
		record[0] = r.Host.Hostname
		record[1] = r.Host.MachineID
		record[2] = r.Host.OSID
		record[3] = r.Host.OSVersionID
		record[4] = r.Host.Architecture
		record[5] = scannedAt
		record[6] = e.Address
		record[7] = strconv.Itoa(int(e.Port))
		record[8] = e.Protocol
		record[9] = e.Family
		record[10] = string(e.BindScope)
		record[11] = strconv.FormatBool(e.WildcardCoversIPv4)
		record[12] = ""
		if e.PID != 0 {
			record[12] = strconv.Itoa(e.PID)
		}
		record[13] = e.Executable
		record[14] = e.Unit
		record[15] = e.User
		record[16] = e.Container
		record[17], record[18], record[19], record[20], record[21] = "", "", "", "", ""
		if e.Backend != nil {
			record[17] = e.Backend.Address
			if e.Backend.Port != 0 {
				record[18] = strconv.Itoa(int(e.Backend.Port))
			}
			record[19] = e.Backend.Container
			record[20] = e.Backend.Executable
			record[21] = e.Backend.Via
		}
		record[22], record[23] = "", ""
		if e.Image != nil {
			record[22] = e.Image.Ref
			record[23] = e.Image.ManifestDigest
		}
		record[24] = strings.Join(e.Components, multiValueSep)
		record[25] = string(e.Confidence)
		record[26] = strings.Join(e.Evidence, multiValueSep)
		record[27] = ranAsRoot
		record[28] = firewall
		record[29] = blindSpots
		if err := cw.Write(record); err != nil {
			return fmt.Errorf("output: writing exposure csv row for %s:%d: %w", e.Address, e.Port, err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("output: flushing exposure csv: %w", err)
	}
	return nil
}
