package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chaugan/swinv/internal/model"
)

// fixedStart is the only timestamp any test uses; every writer must derive all
// of its time output from it so that repeated writes are byte-identical.
var fixedStart = time.Date(2024, 3, 7, 4, 5, 6, 0, time.FixedZone("CET", 3600))

// sha256 and change were appended in schema 1.1. They are always present, even
// when --hash / --since were not used, so the column shape never varies with
// flags and CSVs stay concatenable across machines and runs.
const wantCSVHeader = "hostname,machine_id,os_id,os_version_id,architecture,scanned_at," +
	"name,version,type,language,purl,cpes,licenses,locations,found_by,sha256,change\n"

// testReport is a report exercising every awkward case at once: embedded
// commas, quotes, newlines and non-ASCII text, multi-valued fields, and a
// component with nothing but the mandatory fields.
func testReport() *model.Report {
	return &model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool: model.Tool{
			Name:        "swinv",
			Version:     "1.2.3",
			Commit:      "deadbeef",
			SyftVersion: "v1.51.0",
		},
		Host: model.Host{
			Hostname:     "host-01",
			FQDN:         "host-01.example.com",
			MachineID:    "3f8d1c2b4a5e6f70",
			OSID:         "ubuntu",
			OSVersionID:  "24.04",
			OSPrettyName: "Ubuntu 24.04.1 LTS",
			Architecture: "amd64",
			IPv4:         []string{"10.0.0.5", "192.168.1.2"},
			MACs:         []string{"aa:bb:cc:dd:ee:ff"},
		},
		Scan: model.ScanMeta{
			StartedAt:  fixedStart,
			FinishedAt: fixedStart.Add(42 * time.Second),
			DurationMS: 42000,
			Root:       "/",
			Excluded:   []string{"./proc/**", "./sys/**"},
			Catalogers: []string{"installed", "directory"},
			RanAsRoot:  true,
			Warnings:   []string{"312 files could not be identified"},
		},
		Components: []model.Component{
			{
				Name:      "café-naïve",
				Version:   "1.0,beta",
				Type:      "deb",
				Language:  "",
				PURL:      "pkg:deb/ubuntu/caf%C3%A9-na%C3%AFve@1.0?arch=amd64",
				CPEs:      []string{`cpe:2.3:a:café:x:1.0:*:*:*:*:*:*:*`, "cpe:2.3:a:other:x:1.0:*:*:*:*:*:*:*"},
				Licenses:  []string{`MIT AND "Weird, License"`, "Apache-2.0"},
				Locations: []string{"/usr/share/doc/x\nnewline", "/var/lib/dpkg/status"},
				FoundBy:   "dpkg-db-cataloger",
			},
			{
				Name:    "minimal",
				Version: "0.0.1",
				Type:    "binary",
			},
			{
				Name:      "left-pad",
				Version:   "1.3.0",
				Type:      "npm",
				Language:  "javascript",
				PURL:      "pkg:npm/left-pad@1.3.0",
				Licenses:  []string{"WTFPL OR MIT"},
				Locations: []string{"/srv/app/node_modules/left-pad/package.json"},
				FoundBy:   "javascript-package-cataloger",
			},
		},
	}
}

func emptyReport() *model.Report {
	r := testReport()
	r.Components = []model.Component{}
	return r
}

func mustWrite(t *testing.T, fn func(io.Writer, *model.Report) error, r *model.Report) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := fn(&buf, r); err != nil {
		t.Fatalf("writer returned error: %v", err)
	}
	return buf.Bytes()
}

func TestWriteCSVHeaderIsExact(t *testing.T) {
	got := string(mustWrite(t, WriteCSV, emptyReport()))
	if got != wantCSVHeader {
		t.Errorf("empty report CSV = %q, want exactly the header %q", got, wantCSVHeader)
	}
	if want := strings.Split(strings.TrimSuffix(wantCSVHeader, "\n"), ","); !reflect.DeepEqual(CSVColumns(), want) {
		t.Errorf("CSVColumns() = %v, want %v", CSVColumns(), want)
	}
}

func TestWriteCSVEscapingAndContent(t *testing.T) {
	r := testReport()
	raw := mustWrite(t, WriteCSV, r)

	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("CSV starts with a UTF-8 BOM")
	}
	if bytes.Contains(raw, []byte("\r\n")) {
		t.Fatal("CSV contains CRLF line endings, want LF only")
	}
	if !bytes.Contains(raw, []byte("café-naïve")) {
		t.Error("non-ASCII component name was not written literally as UTF-8")
	}
	// RFC 4180: an embedded quote is doubled inside a quoted field.
	if !bytes.Contains(raw, []byte(`""Weird, License""`)) {
		t.Errorf("embedded quotes were not doubled; got:\n%s", raw)
	}

	records, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil {
		t.Fatalf("re-parsing our own CSV: %v", err)
	}
	if got, want := len(records), len(r.Components)+1; got != want {
		t.Fatalf("record count = %d, want %d (header + one row per component)", got, want)
	}
	if !reflect.DeepEqual(records[0], CSVColumns()) {
		t.Fatalf("header row = %v, want %v", records[0], CSVColumns())
	}

	// Rows follow component order; the first component is the awkward one.
	row := records[1]
	c := r.Components[0]
	want := []string{
		r.Host.Hostname, r.Host.MachineID, r.Host.OSID, r.Host.OSVersionID, r.Host.Architecture,
		"2024-03-07T03:05:06Z",
		c.Name, c.Version, c.Type, c.Language, c.PURL,
		strings.Join(c.CPEs, ";"),
		strings.Join(c.Licenses, ";"),
		strings.Join(c.Locations, ";"),
		c.FoundBy,
		c.SHA256,
		c.Change,
	}
	if !reflect.DeepEqual(row, want) {
		t.Errorf("row round-trip mismatch:\n got %q\nwant %q", row, want)
	}

	// The minimal component must still produce a full-width row.
	if got := len(records[2]); got != len(csvColumns) {
		t.Errorf("minimal component row has %d fields, want %d", got, len(csvColumns))
	}
}

func TestWriteCSVScannedAtIsUTC(t *testing.T) {
	r := testReport()
	records, err := csv.NewReader(bytes.NewReader(mustWrite(t, WriteCSV, r))).ReadAll()
	if err != nil {
		t.Fatalf("parsing csv: %v", err)
	}
	got := records[1][5]
	if got != "2024-03-07T03:05:06Z" {
		t.Errorf("scanned_at = %q, want the RFC3339 UTC rendering %q", got, "2024-03-07T03:05:06Z")
	}
	if _, err := time.Parse(time.RFC3339, got); err != nil {
		t.Errorf("scanned_at %q is not RFC3339: %v", got, err)
	}
}

func TestWriteJSONRoundTrip(t *testing.T) {
	r := testReport()
	raw := mustWrite(t, WriteJSON, r)

	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Error("JSON output is not newline-terminated")
	}
	if !bytes.Contains(raw, []byte("\n  \"tool\": {")) {
		t.Errorf("JSON is not indented with two spaces; got:\n%s", raw)
	}

	var got model.Report
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("re-parsing our own JSON: %v", err)
	}
	if !reflect.DeepEqual(got.Components, r.Components) {
		t.Errorf("components did not round-trip:\n got %+v\nwant %+v", got.Components, r.Components)
	}
	if !reflect.DeepEqual(got.Host, r.Host) {
		t.Errorf("host did not round-trip:\n got %+v\nwant %+v", got.Host, r.Host)
	}
	if got.SchemaVersion != r.SchemaVersion || got.Tool != r.Tool {
		t.Errorf("tool/schema did not round-trip: %+v", got)
	}
	if !got.Scan.StartedAt.Equal(r.Scan.StartedAt) || !got.Scan.FinishedAt.Equal(r.Scan.FinishedAt) {
		t.Errorf("scan timestamps did not round-trip: %+v", got.Scan)
	}

	// A re-encode of the decoded report must reproduce the bytes exactly.
	again := mustWrite(t, WriteJSON, &got)
	if !bytes.Equal(raw, again) {
		t.Error("re-encoding the decoded report produced different bytes")
	}
}

func TestWriteJSONDoesNotEscapeHTML(t *testing.T) {
	r := emptyReport()
	r.Components = []model.Component{{
		Name:    "x",
		Version: "1",
		Type:    "generic",
		PURL:    "pkg:generic/x@1?a=1&b=2",
	}}
	raw := mustWrite(t, WriteJSON, r)
	if bytes.Contains(raw, []byte(`\u0026`)) {
		t.Errorf("ampersand was HTML-escaped; got:\n%s", raw)
	}
	if !bytes.Contains(raw, []byte("a=1&b=2")) {
		t.Errorf("PURL was not written literally; got:\n%s", raw)
	}
}

func TestWriteNDJSONLines(t *testing.T) {
	r := testReport()
	raw := mustWrite(t, WriteNDJSON, r)

	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatal("NDJSON output is not newline-terminated")
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != len(r.Components) {
		t.Fatalf("line count = %d, want %d", len(lines), len(r.Components))
	}

	for i, line := range lines {
		if strings.Contains(line, "\n") {
			t.Fatalf("line %d contains an embedded newline", i)
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d is not valid JSON: %v (%s)", i, err, line)
		}
		for _, field := range []string{"hostname", "machine_id", "os_id", "os_version_id", "architecture", "scanned_at", "name", "version", "type"} {
			if _, ok := obj[field]; !ok {
				t.Errorf("line %d is missing the self-describing field %q", i, field)
			}
		}
		if obj["hostname"] != r.Host.Hostname {
			t.Errorf("line %d hostname = %v, want %q", i, obj["hostname"], r.Host.Hostname)
		}
		if obj["scanned_at"] != "2024-03-07T03:05:06Z" {
			t.Errorf("line %d scanned_at = %v, want the UTC rendering", i, obj["scanned_at"])
		}
		if obj["name"] != r.Components[i].Name {
			t.Errorf("line %d name = %v, want %q", i, obj["name"], r.Components[i].Name)
		}
	}

	// Optional fields must be omitted rather than emitted empty.
	var minimal map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &minimal); err != nil {
		t.Fatalf("parsing minimal line: %v", err)
	}
	if _, ok := minimal["purl"]; ok {
		t.Error("minimal component emitted an empty purl field")
	}
}

func TestWriteNDJSONEmptyReport(t *testing.T) {
	if raw := mustWrite(t, WriteNDJSON, emptyReport()); len(raw) != 0 {
		t.Errorf("empty report produced %q, want no output", raw)
	}
}

func TestWriteCycloneDX(t *testing.T) {
	r := testReport()
	raw := mustWrite(t, WriteCycloneDX, r)

	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Version     int    `json:"version"`
		Serial      string `json:"serialNumber"`
		Metadata    struct {
			Timestamp string `json:"timestamp"`
			Tools     struct {
				Components []struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"components"`
			} `json:"tools"`
			Component struct {
				Type       string `json:"type"`
				Name       string `json:"name"`
				Properties []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"properties"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			BOMRef   string `json:"bom-ref"`
			Type     string `json:"type"`
			Name     string `json:"name"`
			Version  string `json:"version"`
			PURL     string `json:"purl"`
			CPE      string `json:"cpe"`
			Licenses []struct {
				Expression string `json:"expression"`
				License    *struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
			} `json:"licenses"`
			Evidence struct {
				Occurrences []struct {
					Location string `json:"location"`
				} `json:"occurrences"`
			} `json:"evidence"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("CycloneDX output is not valid JSON: %v\n%s", err, raw)
	}

	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want %q", doc.BOMFormat, "CycloneDX")
	}
	if doc.SpecVersion != "1.6" {
		t.Errorf("specVersion = %q, want %q", doc.SpecVersion, "1.6")
	}
	if doc.Serial != "" {
		t.Errorf("serialNumber = %q, want it omitted so output stays deterministic", doc.Serial)
	}
	if doc.Metadata.Timestamp != "2024-03-07T03:05:06Z" {
		t.Errorf("metadata.timestamp = %q, want the scan start in UTC", doc.Metadata.Timestamp)
	}
	if len(doc.Components) != len(r.Components) {
		t.Fatalf("component count = %d, want %d", len(doc.Components), len(r.Components))
	}

	var sawInvd bool
	for _, tool := range doc.Metadata.Tools.Components {
		if tool.Name == "swinv" && tool.Version == r.Tool.Version {
			sawInvd = true
		}
	}
	if !sawInvd {
		t.Errorf("metadata.tools does not contain swinv: %+v", doc.Metadata.Tools.Components)
	}

	if doc.Metadata.Component.Name != r.Host.Hostname {
		t.Errorf("metadata.component.name = %q, want %q", doc.Metadata.Component.Name, r.Host.Hostname)
	}
	props := map[string]string{}
	for _, p := range doc.Metadata.Component.Properties {
		props[p.Name] = p.Value
	}
	if props["swinv:host:machine_id"] != r.Host.MachineID {
		t.Errorf("host machine_id property = %q, want %q", props["swinv:host:machine_id"], r.Host.MachineID)
	}
	if props["swinv:host:os_id"] != r.Host.OSID {
		t.Errorf("host os_id property = %q, want %q", props["swinv:host:os_id"], r.Host.OSID)
	}

	first := doc.Components[0]
	if first.Type != "library" {
		t.Errorf("component type = %q, want %q", first.Type, "library")
	}
	if first.Name != r.Components[0].Name || first.Version != r.Components[0].Version {
		t.Errorf("component identity = %q@%q, want %q@%q", first.Name, first.Version, r.Components[0].Name, r.Components[0].Version)
	}
	if first.PURL != r.Components[0].PURL {
		t.Errorf("component purl = %q, want %q", first.PURL, r.Components[0].PURL)
	}
	if first.BOMRef != r.Components[0].PURL {
		t.Errorf("component bom-ref = %q, want it derived from the purl", first.BOMRef)
	}
	if first.CPE != r.Components[0].CPEs[0] {
		t.Errorf("component cpe = %q, want the first CPE %q", first.CPE, r.Components[0].CPEs[0])
	}
	if got, want := len(first.Evidence.Occurrences), len(r.Components[0].Locations); got != want {
		t.Errorf("occurrence count = %d, want %d", got, want)
	}
	if len(first.Licenses) != 2 {
		t.Fatalf("licence count = %d, want 2", len(first.Licenses))
	}
	if first.Licenses[0].License == nil || first.Licenses[0].License.Name == "" {
		t.Errorf("free-text licence should map to license.name, got %+v", first.Licenses[0])
	}
	if first.Licenses[1].License == nil || first.Licenses[1].License.ID != "Apache-2.0" {
		t.Errorf("single-token licence should map to license.id, got %+v", first.Licenses[1])
	}

	// A lone SPDX expression is the one case that must use "expression".
	last := doc.Components[2]
	if len(last.Licenses) != 1 || last.Licenses[0].Expression != "WTFPL OR MIT" {
		t.Errorf("lone SPDX expression not emitted as an expression: %+v", last.Licenses)
	}
}

func TestWriteCycloneDXEmptyReport(t *testing.T) {
	raw := mustWrite(t, WriteCycloneDX, emptyReport())
	var doc struct {
		Components []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("CycloneDX output for an empty report is not valid JSON: %v", err)
	}
	if len(doc.Components) != 0 {
		t.Errorf("component count = %d, want 0", len(doc.Components))
	}
}

func TestWriteCycloneDXHostnameFallback(t *testing.T) {
	r := emptyReport()
	r.Host.Hostname = ""
	raw := mustWrite(t, WriteCycloneDX, r)
	if !bytes.Contains(raw, []byte("unknown-host")) {
		t.Errorf("missing hostname did not fall back to a placeholder name:\n%s", raw)
	}
}

func TestDeterminism(t *testing.T) {
	for _, format := range Formats() {
		t.Run(format, func(t *testing.T) {
			fn, _, err := WriterFor(format)
			if err != nil {
				t.Fatalf("WriterFor(%q): %v", format, err)
			}
			first := mustWrite(t, fn, testReport())
			second := mustWrite(t, fn, testReport())
			if !bytes.Equal(first, second) {
				t.Errorf("format %q is not deterministic:\nfirst:\n%s\nsecond:\n%s", format, first, second)
			}
			if len(first) == 0 {
				t.Errorf("format %q produced no output", format)
			}
		})
	}
}

func TestWriterFor(t *testing.T) {
	cases := []struct {
		format string
		ext    string
	}{
		{"json", ".json"},
		{"csv", ".csv"},
		{"ndjson", ".ndjson"},
		{"cyclonedx-json", ".cdx.json"},
		{"  CycloneDX-JSON  ", ".cdx.json"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			fn, ext, err := WriterFor(tc.format)
			if err != nil {
				t.Fatalf("WriterFor(%q) returned error: %v", tc.format, err)
			}
			if fn == nil {
				t.Fatal("WriterFor returned a nil writer")
			}
			if ext != tc.ext {
				t.Errorf("extension = %q, want %q", ext, tc.ext)
			}
			if err := fn(io.Discard, testReport()); err != nil {
				t.Errorf("returned writer failed: %v", err)
			}
		})
	}

	if _, _, err := WriterFor("yaml"); !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("WriterFor(\"yaml\") error = %v, want it to wrap ErrUnknownFormat", err)
	}
	if got, want := Formats(), []string{"csv", "cyclonedx-json", "json", "ndjson"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Formats() = %v, want %v", got, want)
	}
}

func TestWritersRejectNilReport(t *testing.T) {
	for _, format := range Formats() {
		fn, _, err := WriterFor(format)
		if err != nil {
			t.Fatalf("WriterFor(%q): %v", format, err)
		}
		if err := fn(io.Discard, nil); !errors.Is(err, ErrNilReport) {
			t.Errorf("%s writer with nil report: err = %v, want ErrNilReport", format, err)
		}
	}
}

func TestAtomicWriteFileSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")

	if err := AtomicWriteFile(path, 0o640, func(w io.Writer) error {
		_, err := io.WriteString(w, "hello\n")
		return err
	}); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading target: %v", err)
	}
	if string(got) != "hello\n" {
		t.Errorf("contents = %q, want %q", got, "hello\n")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("mode = %o, want %o", perm, 0o640)
	}
	assertNoTempFiles(t, dir)
}

func TestAtomicWriteFileModeIsIndependentOfUmask(t *testing.T) {
	old := syscallUmask(0o077)
	defer syscallUmask(old)

	dir := t.TempDir()
	path := filepath.Join(dir, "wide.csv")
	if err := AtomicWriteFile(path, 0o644, func(w io.Writer) error { return nil }); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %o, want %o even under a restrictive umask", perm, 0o644)
	}
}

func TestAtomicWriteFileFailureLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.csv")
	if err := os.WriteFile(path, []byte("previous\n"), 0o644); err != nil {
		t.Fatalf("seeding existing target: %v", err)
	}

	sentinel := errors.New("writer exploded")
	err := AtomicWriteFile(path, 0o644, func(w io.Writer) error {
		if _, err := io.WriteString(w, "partial data that must never land"); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap the writer's error", err)
	}

	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("existing target was removed: %v", readErr)
	}
	if string(got) != "previous\n" {
		t.Errorf("existing target was clobbered: %q", got)
	}
	assertNoTempFiles(t, dir)
}

func TestAtomicWriteFileFailureDoesNotCreateTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh.json")

	if err := AtomicWriteFile(path, 0o644, func(w io.Writer) error {
		return errors.New("nope")
	}); err == nil {
		t.Fatal("AtomicWriteFile returned nil for a failing writer")
	}

	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("target exists after a failed write (stat err = %v)", err)
	}
	assertNoTempFiles(t, dir)
}

func TestAtomicWriteFileRejectsNilFunc(t *testing.T) {
	if err := AtomicWriteFile(filepath.Join(t.TempDir(), "x"), 0o644, nil); err == nil {
		t.Error("AtomicWriteFile with a nil write function returned nil")
	}
}

func TestAtomicWriteFileReplacesStaleTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	stale := path + ".tmp-" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(stale, []byte("debris"), 0o600); err != nil {
		t.Fatalf("seeding stale temp file: %v", err)
	}

	if err := AtomicWriteFile(path, 0o644, func(w io.Writer) error {
		_, err := io.WriteString(w, "fresh")
		return err
	}); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "fresh" {
		t.Errorf("contents = %q (err %v), want %q", got, err, "fresh")
	}
	assertNoTempFiles(t, dir)
}

func TestAtomicWriteFileWithRealReport(t *testing.T) {
	dir := t.TempDir()
	r := testReport()
	for _, format := range Formats() {
		fn, ext, err := WriterFor(format)
		if err != nil {
			t.Fatalf("WriterFor(%q): %v", format, err)
		}
		path := filepath.Join(dir, "host-01"+ext)
		if err := AtomicWriteFile(path, 0o644, func(w io.Writer) error { return fn(w, r) }); err != nil {
			t.Fatalf("AtomicWriteFile(%s): %v", format, err)
		}
		onDisk, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if !bytes.Equal(onDisk, mustWrite(t, fn, r)) {
			t.Errorf("%s: file contents differ from the writer's output", format)
		}
	}
	assertNoTempFiles(t, dir)
}

func TestUpdateSymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "host-01-latest.json")

	first := filepath.Join(dir, "host-01-20240306.json")
	if err := os.WriteFile(first, []byte("one"), 0o644); err != nil {
		t.Fatalf("writing first target: %v", err)
	}
	if err := UpdateSymlink(link, first); err != nil {
		t.Fatalf("UpdateSymlink: %v", err)
	}

	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != "host-01-20240306.json" {
		t.Errorf("target = %q, want the bare basename", target)
	}

	// Replacing an existing symlink must succeed and must repoint it.
	second := filepath.Join(dir, "host-01-20240307.json")
	if err := os.WriteFile(second, []byte("two"), 0o644); err != nil {
		t.Fatalf("writing second target: %v", err)
	}
	if err := UpdateSymlink(link, second); err != nil {
		t.Fatalf("UpdateSymlink over an existing link: %v", err)
	}
	target, err = os.Readlink(link)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != "host-01-20240307.json" {
		t.Errorf("target = %q, want %q", target, "host-01-20240307.json")
	}
	got, err := os.ReadFile(link)
	if err != nil {
		t.Fatalf("reading through the link: %v", err)
	}
	if string(got) != "two" {
		t.Errorf("link resolves to %q, want %q", got, "two")
	}
	assertNoTempFiles(t, dir)
}

func TestUpdateSymlinkKeepsForeignTargetAbsolute(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(other, []byte("x"), 0o644); err != nil {
		t.Fatalf("writing target: %v", err)
	}
	link := filepath.Join(dir, "latest.json")
	if err := UpdateSymlink(link, other); err != nil {
		t.Fatalf("UpdateSymlink: %v", err)
	}
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != other {
		t.Errorf("target = %q, want the absolute path %q", target, other)
	}
}

func TestUpdateSymlinkRejectsEmptyArguments(t *testing.T) {
	if err := UpdateSymlink("", "target"); err == nil {
		t.Error("empty link path was accepted")
	}
	if err := UpdateSymlink(filepath.Join(t.TempDir(), "l"), ""); err == nil {
		t.Error("empty target was accepted")
	}
}

// assertNoTempFiles fails if any staging file survived in dir.
func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file %s was left behind in %s", e.Name(), dir)
		}
	}
}
