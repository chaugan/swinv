package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chaugan/swinv/internal/htmlreport"
	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/output"
)

// loadReportForHTML reads a previously written swinv report and reconstructs a
// model.Report for the HTML renderer, without running a new scan. It accepts
// two shapes:
//
//   - a JSON report (the --format json file): unmarshalled directly.
//   - an NDJSON stream (the --format ndjson file): rebuilt line by line.
//
// NDJSON is a denormalised projection of the report, so the reconstruction is
// faithful to what the stream actually carried, not to what a fresh scan would
// find: a port attributed to three packages is one listener again, exposure
// counts collapse back to one row per socket, and a --heartbeat stream that
// suppressed its component records yields a report with none. That is the
// correct behaviour - the page reports the file, not the machine.
func loadReportForHTML(path string) (*model.Report, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied report path
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if looksLikeJSONReport(raw) {
		var r model.Report
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("parsing %s as an swinv JSON report: %w", path, err)
		}
		if r.SchemaVersion == "" {
			return nil, fmt.Errorf("%s does not look like an swinv report (no schema_version)", path)
		}
		return &r, nil
	}
	return reconstructFromNDJSON(raw, path)
}

// looksLikeJSONReport decides between a single JSON object (the json format)
// and a newline-delimited stream (ndjson). Both begin with '{'; the report is
// a pretty-printed object whose first record_type-free line is not itself a
// complete JSON object, whereas every NDJSON line is.
func looksLikeJSONReport(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	// A pretty-printed JSON report has "schema_version" near the top and its
	// first line is just "{". An NDJSON stream's first line is a whole object.
	firstLine := trimmed
	if i := bytes.IndexByte(trimmed, '\n'); i >= 0 {
		firstLine = bytes.TrimSpace(trimmed[:i])
	}
	if string(firstLine) == "{" {
		return true
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(firstLine, &probe); err != nil {
		// First line is not a standalone object -> a pretty-printed report.
		return true
	}
	// A standalone first object that is a component or a record is NDJSON.
	_, hasSchema := probe["schema_version"]
	_, hasComponents := probe["components"]
	return hasSchema && hasComponents
}

// reconstructFromNDJSON rebuilds a report from the newline-delimited stream.
func reconstructFromNDJSON(raw []byte, path string) (*model.Report, error) {
	r := &model.Report{SchemaVersion: model.SchemaVersion}
	linksByExe := map[string]int{} // executable -> index into r.Links
	expByKey := map[string]int{}   // addr|port|proto -> index into r.Exposure
	var parsed int

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var probe struct {
			RecordType string `json:"record_type"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return nil, fmt.Errorf("%s:%d: not JSON: %w", path, lineNo, err)
		}
		parsed++
		switch probe.RecordType {
		case "", model.RecordComponent:
			ndjsonComponent(r, line)
		case model.RecordHeartbeat:
			ndjsonHeartbeat(r, line)
		case model.RecordLink:
			ndjsonLink(r, line, linksByExe)
		case model.RecordConfig:
			ndjsonConfig(r, line)
		case model.RecordExposure:
			ndjsonExposure(r, line, expByKey)
		case model.RecordContainer:
			ndjsonContainer(r, line)
		default:
			// An unknown record_type from a newer swinv: skip it rather than
			// fail, the same tolerance the JSON path shows an unknown schema.
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if parsed == 0 {
		return nil, fmt.Errorf("%s is empty - no records to report on", path)
	}
	return r, nil
}

func ndjsonComponent(r *model.Report, line []byte) {
	var c struct {
		Hostname    string `json:"hostname"`
		OSID        string `json:"os_id"`
		OSVersionID string `json:"os_version_id"`
		Name        string `json:"name"`
		Version     string `json:"version"`
		Type        string `json:"type"`
		PURL        string `json:"purl"`
		Root        string `json:"root"`
		SourceKey   string `json:"source_key"`
		SHA256      string `json:"sha256"`
	}
	if json.Unmarshal(line, &c) != nil {
		return
	}
	fillHostIdentity(r, c.Hostname, c.OSID, c.OSVersionID)
	r.Components = append(r.Components, model.Component{
		Name:      c.Name,
		Version:   c.Version,
		Type:      c.Type,
		PURL:      c.PURL,
		Root:      c.Root,
		SourceKey: c.SourceKey,
		SHA256:    c.SHA256,
	})
}

func ndjsonHeartbeat(r *model.Report, line []byte) {
	var h struct {
		Hostname     string                        `json:"hostname"`
		OSID         string                        `json:"os_id"`
		OSVersionID  string                        `json:"os_version_id"`
		Architecture string                        `json:"architecture"`
		ScannedAt    string                        `json:"scanned_at"`
		SwinvVersion string                        `json:"swinv_version"`
		Sources      map[string]model.SourceStatus `json:"sources"`
		ScanProfile  *model.ScanProfile            `json:"scan_profile"`
	}
	if json.Unmarshal(line, &h) != nil {
		return
	}
	fillHostIdentity(r, h.Hostname, h.OSID, h.OSVersionID)
	if r.Host.Architecture == "" {
		r.Host.Architecture = h.Architecture
	}
	if h.SwinvVersion != "" {
		r.Tool.Version = h.SwinvVersion
	}
	if len(h.Sources) > 0 {
		if r.Scan.Sources == nil {
			r.Scan.Sources = map[string]model.SourceStatus{}
		}
		for k, v := range h.Sources {
			r.Scan.Sources[k] = v
		}
	}
	if h.ScanProfile != nil {
		r.Scan.Profile = h.ScanProfile
	}
	if r.Scan.StartedAt.IsZero() && h.ScannedAt != "" {
		if t, err := parseScannedAt(h.ScannedAt); err == nil {
			r.Scan.StartedAt = t
		}
	}
}

func ndjsonLink(r *model.Report, line []byte, byExe map[string]int) {
	var l struct {
		Executable     string `json:"executable"`
		ExecutablePURL string `json:"executable_purl"`
		Soname         string `json:"soname"`
		Path           string `json:"path"`
		PURL           string `json:"purl"`
		Transitive     bool   `json:"transitive"`
		OSComponent    bool   `json:"os_component"`
	}
	if json.Unmarshal(line, &l) != nil {
		return
	}
	idx, ok := byExe[l.Executable]
	if !ok {
		r.Links = append(r.Links, model.BinaryLinks{Executable: l.Executable, PURL: l.ExecutablePURL})
		idx = len(r.Links) - 1
		byExe[l.Executable] = idx
	}
	r.Links[idx].Links = append(r.Links[idx].Links, model.Link{
		Soname:      l.Soname,
		Path:        l.Path,
		PURL:        l.PURL,
		Transitive:  l.Transitive,
		OSComponent: l.OSComponent,
	})
}

func ndjsonConfig(r *model.Report, line []byte) {
	var c struct {
		Kind          string `json:"kind"`
		Name          string `json:"name"`
		Path          string `json:"path"`
		User          string `json:"user"`
		Executable    string `json:"executable"`
		PURL          string `json:"purl"`
		Attack        string `json:"attack"`
		WorldWritable bool   `json:"world_writable"`
		EvidenceText  string `json:"evidence_text"`
	}
	if json.Unmarshal(line, &c) != nil {
		return
	}
	var evidence []string
	if c.EvidenceText != "" {
		evidence = strings.Split(c.EvidenceText, "; ")
	}
	r.ConfigSurface = append(r.ConfigSurface, model.ConfigEntry{
		Kind:          c.Kind,
		Name:          c.Name,
		Path:          c.Path,
		User:          c.User,
		Executable:    c.Executable,
		PURL:          c.PURL,
		Attack:        c.Attack,
		WorldWritable: c.WorldWritable,
		Evidence:      evidence,
	})
}

func ndjsonExposure(r *model.Report, line []byte, byKey map[string]int) {
	var e struct {
		Address    string `json:"address"`
		Port       uint16 `json:"port"`
		Protocol   string `json:"protocol"`
		Family     string `json:"family"`
		BindScope  string `json:"bind_scope"`
		PURL       string `json:"purl"`
		Executable string `json:"executable"`
		Unit       string `json:"unit"`
		User       string `json:"user"`
		Confidence string `json:"confidence"`
	}
	if json.Unmarshal(line, &e) != nil {
		return
	}
	key := fmt.Sprintf("%s|%d|%s", e.Address, e.Port, e.Protocol)
	if idx, ok := byKey[key]; ok {
		// Same socket, another attributed package: fold the PURL in rather
		// than emit a second listener row.
		if e.PURL != "" {
			r.Exposure[idx].Components = append(r.Exposure[idx].Components, e.PURL)
		}
		return
	}
	exp := model.Exposure{
		Address:    e.Address,
		Port:       e.Port,
		Protocol:   e.Protocol,
		Family:     e.Family,
		BindScope:  model.BindScope(e.BindScope),
		Executable: e.Executable,
		Unit:       e.Unit,
		User:       e.User,
		Confidence: model.Confidence(e.Confidence),
	}
	if e.PURL != "" {
		exp.Components = []string{e.PURL}
	}
	r.Exposure = append(r.Exposure, exp)
	byKey[key] = len(r.Exposure) - 1
}

func ndjsonContainer(r *model.Report, line []byte) {
	var c struct {
		ContainerID   string `json:"container_id"`
		ContainerName string `json:"container_name"`
		Runtime       string `json:"runtime"`
		State         string `json:"state"`
		ImageRef      string `json:"image_ref"`
		OSID          string `json:"os_id"`
		OSVersionID   string `json:"os_version_id"`
	}
	if json.Unmarshal(line, &c) != nil {
		return
	}
	ct := model.Container{
		ID:          c.ContainerID,
		Name:        c.ContainerName,
		Runtime:     c.Runtime,
		State:       c.State,
		OSID:        c.OSID,
		OSVersionID: c.OSVersionID,
	}
	if c.ImageRef != "" {
		ct.Image = &model.Image{Ref: c.ImageRef}
	}
	r.Containers = append(r.Containers, ct)
}

func fillHostIdentity(r *model.Report, hostname, osID, osVersion string) {
	if r.Host.Hostname == "" {
		r.Host.Hostname = hostname
	}
	if r.Host.OSID == "" {
		r.Host.OSID = osID
	}
	if r.Host.OSVersionID == "" {
		r.Host.OSVersionID = osVersion
	}
}

// writeHTMLReport renders r to path as a self-contained HTML page.
func writeHTMLReport(path string, perm os.FileMode, r *model.Report, logf func(string, ...any), stderr io.Writer) int {
	if err := renderHTMLReport(path, perm, r); err != nil {
		fmt.Fprintf(stderr, "swinv: writing HTML report %s: %v\n", path, err)
		return exitFatal
	}
	logf("wrote %s", path)
	return exitOK
}

// parseScannedAt accepts the RFC3339 timestamps swinv writes into records.
func parseScannedAt(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

// renderHTMLReport writes the self-contained HTML page atomically, replacing
// any existing file at path.
//
// The two guards exist because --html-report takes an arbitrary path, unlike
// the other outputs which land in --out under a generated name. A directory at
// path cannot be replaced by a file: the atomic rename fails, and on Windows
// that failure reads as a silent no-op - the report is not written and nothing
// says so. Catching it here turns that into one clear line. And the parent
// directory is created if missing, so a fresh path just works rather than
// failing when the staging file cannot be created.
func renderHTMLReport(path string, perm os.FileMode, r *model.Report) error {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		return fmt.Errorf("%s is a directory; --html-report needs a file path, e.g. %s",
			path, filepath.Join(path, "report.html"))
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- a report page is not secret
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	if err := output.AtomicWriteFile(path, perm, func(w io.Writer) error {
		return htmlreport.WriteHTML(w, r)
	}); err != nil {
		return err
	}
	// Confirm the file is actually there and non-empty, so a "wrote" line is
	// never printed for a write that did not land.
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("report was not written to %s: %w", path, err)
	}
	if fi.IsDir() || fi.Size() == 0 {
		return fmt.Errorf("report at %s is empty after writing", path)
	}
	return nil
}
