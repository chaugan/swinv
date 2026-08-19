// Package output renders a model.Report into the on-disk formats swinv
// supports — JSON, CSV, NDJSON, and CycloneDX 1.6 JSON — and provides the
// atomic file-replacement primitives the writers are used with.
//
// Two rules govern everything in this package:
//
//   - Determinism. Writing the same Report twice must produce byte-identical
//     bytes for every format. Nothing here reads the wall clock, generates a
//     random identifier, or iterates a map without sorting it first. That is
//     what makes daily inventory files diffable, which is the main reason to
//     keep them on disk at all.
//   - Atomicity. A half-written inventory file that a collector picks up is
//     worse than no file, so files are staged next to their target, fsynced,
//     and renamed into place. See AtomicWriteFile.
//
// This package must not import Syft; it operates purely on internal/model
// types, which is what keeps a Syft API break contained to internal/scan.
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/chrzz/swinv/internal/model"
)

// ErrNilReport is returned by every writer when it is handed a nil report.
var ErrNilReport = errors.New("output: nil report")

// ErrUnknownFormat is returned by WriterFor for a format name that is not one
// of "json", "csv", "ndjson", or "cyclonedx-json".
var ErrUnknownFormat = errors.New("output: unknown format")

// WriteJSON writes the report as a single indented JSON document, terminated
// by a newline. HTML escaping is disabled so that URLs, PURLs, and CPEs are
// written literally rather than with <-style escapes.
//
// It does not close w.
func WriteJSON(w io.Writer, r *model.Report) error {
	if r == nil {
		return ErrNilReport
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("output: encoding json: %w", err)
	}
	return nil
}

// writerEntry is one row of the format registry.
type writerEntry struct {
	write func(io.Writer, *model.Report) error
	ext   string
}

// writers is the format registry backing WriterFor and Formats. Extensions
// include the leading dot so a filename is basename+ext.
var writers = map[string]writerEntry{
	"json":           {WriteJSON, ".json"},
	"csv":            {WriteCSV, ".csv"},
	"ndjson":         {WriteNDJSON, ".ndjson"},
	"cyclonedx-json": {WriteCycloneDX, ".cdx.json"},
}

// WriterFor resolves a format name to its writer function and the file
// extension (including the leading dot) that output should be given.
//
// The recognised names are "json", "csv", "ndjson", and "cyclonedx-json";
// matching ignores surrounding whitespace and letter case. An unrecognised
// name yields an error wrapping ErrUnknownFormat, which the caller should
// treat as a usage error.
func WriterFor(format string) (func(io.Writer, *model.Report) error, string, error) {
	name := strings.ToLower(strings.TrimSpace(format))
	entry, ok := writers[name]
	if !ok {
		return nil, "", fmt.Errorf("%w %q (want one of: %s)", ErrUnknownFormat, format, strings.Join(Formats(), ", "))
	}
	return entry.write, entry.ext, nil
}

// Formats returns the recognised format names in sorted order, suitable for
// use in CLI help text and error messages.
func Formats() []string {
	out := make([]string, 0, len(writers))
	for name := range writers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
