package transmit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/chaugan/swinv/internal/output"
)

// SpoolDirName is the directory, under --out, where scans awaiting upload sit.
//
// A dotted directory next to the reports, matching the convention the
// heartbeat state already set: a collector globbing *.json or *.ndjson does not
// pick it up, and removing --out removes the queue with it rather than leaving
// scans behind that will be uploaded months later as though they were current.
const SpoolDirName = ".swinv-spool"

const (
	spoolPayloadExt = ".ndjson"
	spoolStateExt   = ".state.json"
)

// SpoolState is what survives a process that dies mid-upload.
//
// Everything needed to finish the upload without rescanning the machine. In
// particular the batch sizes: they define where the batch boundaries fall, so
// a resume that used different ones would send batch 4 containing records the
// server already stored as part of its batch 3, and the idempotency key would
// not save it because the index would look new.
type SpoolState struct {
	ScanID   string    `json:"scan_id"`
	Endpoint string    `json:"endpoint"`
	Hostname string    `json:"hostname"`
	Created  time.Time `json:"created_at"`

	BatchLines int `json:"batch_lines"`
	BatchBytes int `json:"batch_bytes"`

	// Acked is the number of batches the server has confirmed, so batch index
	// Acked is the next one to send. Only ever advanced after a 2xx.
	Acked int `json:"acked_batches"`

	// Declared is what the manifest claims, kept here so a resumed upload can
	// state the same number without re-parsing the payload.
	Declared int `json:"declared_components"`
}

// Spool is one scan's NDJSON, on disk, plus the record of how much of it the
// server has taken.
type Spool struct {
	dir     string
	name    string // the spool's basename, without extension
	perm    os.FileMode
	dirPerm os.FileMode
	state   SpoolState
}

// State returns a copy of the upload state.
func (s *Spool) State() SpoolState { return s.state }

// PayloadPath is the NDJSON file this spool will upload.
func (s *Spool) PayloadPath() string { return filepath.Join(s.dir, s.name+spoolPayloadExt) }

func (s *Spool) statePath() string { return filepath.Join(s.dir, s.name+spoolStateExt) }

// NewSpool writes a scan's NDJSON to the spool directory and records the state
// that makes it resumable.
//
// The payload is written before the state file, and both atomically. A crash
// between the two leaves an orphan payload with no state, which Pending
// ignores -- one wasted scan. The other order would leave a state file
// pointing at a payload that does not exist, and a resume would report a
// missing file for a scan that was never written.
func (c *Client) NewSpool(dir, scanID, hostname string, declared int, _, _ os.FileMode, write func(io.Writer) error) (*Spool, error) {
	// The spool always holds the complete scan, including whatever the report
	// permission chose to share; but the spool is swinv's private staging
	// area, not a file anyone was meant to read, and it lives under a
	// world-traversable --out on a machine with unprivileged local users.
	// Owner-only regardless of the caller's --perm, so a widened report mode
	// cannot widen the spool. See docs/SECURITY.md (R4). The two mode
	// parameters are ignored deliberately and kept for call-site
	// compatibility.
	const perm, dirPerm = os.FileMode(0o600), os.FileMode(0o700)
	// #nosec G301 -- forced to 0700 here
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("transmit: creating the spool directory %s: %w", dir, err)
	}
	s := &Spool{
		dir:     dir,
		name:    sanitizeSpoolName(scanID),
		perm:    perm,
		dirPerm: dirPerm,
		state: SpoolState{
			ScanID:     scanID,
			Endpoint:   c.base,
			Hostname:   hostname,
			Created:    time.Now().UTC(),
			BatchLines: c.opts.BatchLines,
			BatchBytes: c.opts.BatchBytes,
			Declared:   declared,
		},
	}
	if err := output.AtomicWriteFile(s.PayloadPath(), perm, write); err != nil {
		return nil, fmt.Errorf("transmit: spooling the scan: %w", err)
	}
	if err := s.saveState(); err != nil {
		_ = os.Remove(s.PayloadPath())
		return nil, err
	}
	return s, nil
}

// Pending lists spooled scans for one endpoint that were never finished,
// oldest first.
//
// Oldest first so a backlog drains in the order it accumulated: a host that
// was offline for six hours reports its six scans as a history rather than as
// six copies of "now" in an arbitrary order.
func Pending(dir, endpoint string) ([]*Spool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("transmit: reading the spool directory %s: %w", dir, err)
	}

	var out []*Spool
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), spoolStateExt) {
			continue
		}
		name := strings.TrimSuffix(e.Name(), spoolStateExt)
		s, err := loadSpool(dir, name)
		if err != nil {
			// A state file that cannot be read is debris, not a reason to
			// abandon every other queued scan. It is named here rather than
			// silently skipped so that a directory quietly filling with
			// unreadable spools is visible.
			return out, fmt.Errorf("transmit: spool %s: %w", name, err)
		}
		if endpoint == "" {
			out = append(out, s)
			continue
		}
		if s.state.Endpoint != endpoint {
			// A queue built for a different server. Re-pointing --transmit is
			// a deliberate act and its backlog is not ours to deliver.
			continue
		}
		if _, err := os.Stat(s.PayloadPath()); err != nil {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].state.Created.Before(out[j].state.Created) })
	return out, nil
}

func loadSpool(dir, name string) (*Spool, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name+spoolStateExt)) // #nosec G304 -- name comes from ReadDir on our own directory
	if err != nil {
		return nil, err
	}
	var st SpoolState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("the state file is not valid JSON: %w", err)
	}
	if st.BatchLines <= 0 || st.BatchBytes <= 0 {
		return nil, fmt.Errorf("the state file records no batch sizes, so the batch boundaries cannot be reproduced")
	}
	info, err := os.Stat(filepath.Join(dir, name+spoolStateExt))
	perm := os.FileMode(0o600)
	dirPerm := os.FileMode(0o700)
	if err == nil {
		perm = info.Mode().Perm()
	}
	if di, err := os.Stat(dir); err == nil {
		dirPerm = di.Mode().Perm()
	}
	return &Spool{dir: dir, name: name, perm: perm, dirPerm: dirPerm, state: st}, nil
}

// SetScanID adopts a scan id the server minted, and renames the spool to match
// so a later resume finds it under the identifier the server knows.
func (s *Spool) SetScanID(id string) error {
	newName := sanitizeSpoolName(id)
	if newName == s.name {
		s.state.ScanID = id
		return s.saveState()
	}
	oldPayload, oldState := s.PayloadPath(), s.statePath()
	s.name = newName
	s.state.ScanID = id
	if err := os.Rename(oldPayload, s.PayloadPath()); err != nil {
		return fmt.Errorf("transmit: renaming the spool payload: %w", err)
	}
	if err := s.saveState(); err != nil {
		return err
	}
	_ = os.Remove(oldState)
	return nil
}

// Ack records that the server has taken batch index, and everything before it.
func (s *Spool) Ack(index int) error {
	if index+1 <= s.state.Acked {
		return nil
	}
	s.state.Acked = index + 1
	return s.saveState()
}

// Done removes the spool once the server has accepted and reconciled the scan.
func (s *Spool) Done() error {
	var firstErr error
	for _, p := range []string{s.PayloadPath(), s.statePath()} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) && firstErr == nil {
			firstErr = fmt.Errorf("transmit: removing %s: %w", p, err)
		}
	}
	return firstErr
}

func (s *Spool) saveState() error {
	return output.AtomicWriteFile(s.statePath(), s.perm, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(s.state)
	})
}

// Manifest returns line 1 of the payload: the self-describing heartbeat.
//
// It is an error for it to be missing. The manifest is the only thing that
// lets the server reconcile what it stored against what was sent, and a scan
// uploaded without one is precisely the pipeline that cannot tell "nothing to
// find" from "nothing arrived".
func (s *Spool) Manifest() ([]byte, error) {
	f, err := os.Open(s.PayloadPath()) // #nosec G304 -- our own spool file
	if err != nil {
		return nil, fmt.Errorf("transmit: reading the spooled scan: %w", err)
	}
	defer func() { _ = f.Close() }()

	line, err := bufio.NewReaderSize(f, 1<<20).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("transmit: reading the manifest: %w", err)
	}
	line = trimNewline(line)
	if len(line) == 0 {
		return nil, fmt.Errorf("transmit: the spooled scan %s is empty", s.PayloadPath())
	}

	var probe struct {
		RecordType string `json:"record_type"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return nil, fmt.Errorf("transmit: the first line of the spooled scan is not JSON: %w", err)
	}
	if probe.RecordType != "heartbeat" {
		return nil, fmt.Errorf(
			"transmit: the spooled scan begins with a %q record, not the manifest; "+
				"without it the server cannot check what it stored against what was sent",
			probe.RecordType)
	}
	return line, nil
}

// EachBatch walks the payload's record lines in batches, calling fn with the
// batch index, its body, and how many lines it holds.
//
// The manifest line is skipped: it was already delivered by the open call, and
// sending it again as a record would have the server store the scan's own
// description as though it were part of the inventory.
//
// Boundaries come from the recorded state rather than from current flags, so
// batch 7 means the same records on a resume as it did on the run that died.
func (s *Spool) EachBatch(fn func(index int, body []byte, lines int) error) error {
	f, err := os.Open(s.PayloadPath()) // #nosec G304 -- our own spool file
	if err != nil {
		return fmt.Errorf("transmit: reading the spooled scan: %w", err)
	}
	defer func() { _ = f.Close() }()

	// A plain Reader rather than a Scanner: bufio.Scanner refuses a token
	// larger than its buffer, and one component record with a large attribute
	// map would end the upload at that line with "token too long" and no
	// indication that the rest of the host was never sent.
	r := bufio.NewReaderSize(f, 256<<10)

	var (
		batch   []byte
		lines   int
		index   int
		lineNum int
	)
	flush := func() error {
		if lines == 0 {
			return nil
		}
		if err := fn(index, batch, lines); err != nil {
			return err
		}
		index++
		batch = nil
		lines = 0
		return nil
	}

	for {
		raw, readErr := r.ReadBytes('\n')
		line := trimNewline(raw)
		if len(line) > 0 {
			lineNum++
			if lineNum > 1 { // line 1 is the manifest
				// Flush before adding when this line would take the batch past
				// the byte limit, but never produce an empty batch: a single
				// line larger than the limit goes on its own, because the
				// alternative is an upload that stalls forever on one record.
				if lines > 0 && len(batch)+len(line)+1 > s.state.BatchBytes {
					if err := flush(); err != nil {
						return err
					}
				}
				batch = append(batch, line...)
				batch = append(batch, '\n')
				lines++
				if lines >= s.state.BatchLines {
					if err := flush(); err != nil {
						return err
					}
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return fmt.Errorf("transmit: reading the spooled scan: %w", readErr)
		}
	}
	return flush()
}

// Records counts the record lines the payload will send, excluding the
// manifest. It is what the transmitted total is checked against.
func (s *Spool) Records() (int, error) {
	n := 0
	err := s.EachBatch(func(_ int, _ []byte, lines int) error {
		n += lines
		return nil
	})
	return n, err
}

// trimNewline drops the record terminator, and a CR before it.
//
// The CR matters: a spool file that has been through a Windows editor, or a
// payload written on Windows and carried to a Unix host, otherwise sends every
// line with a trailing \r inside the JSON framing, and a strict decoder rejects
// the lot.
func trimNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

// sanitizeSpoolName keeps a server-supplied scan id from naming a path.
//
// The id can come back from the server, which makes it untrusted input, and it
// is used as a filename. Anything outside the identifier alphabet is dropped
// rather than escaped, so "../../etc/cron.d/x" becomes "etccrondx" and lands
// harmlessly inside the spool directory.
func sanitizeSpoolName(id string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return -1
		}
	}, id)
	if out == "" {
		return "scan"
	}
	const max = 64
	if len(out) > max {
		out = out[:max]
	}
	return out
}
