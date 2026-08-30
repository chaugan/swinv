package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/output"
)

// heartbeatStateFile is where the previous scan's digest is remembered.
//
// A dotfile in the output directory, deliberately: it sits next to the reports
// it describes, a collector globbing *.json or *.csv does not pick it up, and
// removing the output directory removes the state with it rather than leaving
// a stale digest behind to claim a fresh machine is unchanged.
const heartbeatStateFile = ".swinv-heartbeat.json"

// heartbeatState is what swinv remembers between runs.
//
// This is the only state swinv keeps, and it is kept grudgingly. Everything
// else about the tool is a pure function of the machine at a point in time.
// The rule that follows from that: any problem reading this file means a full
// scan is emitted. Losing it costs one redundant full send; trusting it
// wrongly costs a silent gap in what a fleet believes is installed.
type heartbeatState struct {
	Hosts map[string]heartbeatHost `json:"hosts"`
}

type heartbeatHost struct {
	Digest string    `json:"digest"`
	FullAt time.Time `json:"full_emitted_at"`
}

// readHeartbeatState loads the previous digests, or returns an empty state.
//
// Every failure is silent and empty by design: a missing file is the first run
// on this host, and a corrupt one is a file somebody edited or a disk that
// lied. Both mean the same thing -- nothing is known about the previous scan,
// so send everything.
func readHeartbeatState(dir string) heartbeatState {
	empty := heartbeatState{Hosts: map[string]heartbeatHost{}}

	raw, err := os.ReadFile(filepath.Join(dir, heartbeatStateFile))
	if err != nil {
		return empty
	}
	var state heartbeatState
	if err := json.Unmarshal(raw, &state); err != nil || state.Hosts == nil {
		return empty
	}
	return state
}

// writeHeartbeatState records this scan's digest for the next one.
//
// It does not create the output directory. Creation and vetting belong to
// ensureOutputDir, which runs before the scan and is the only thing allowed
// to make --out: on Windows, a directory created here with a plain MkdirAll
// would carry the parent's inherited ACLs instead of the admin-only DACL the
// guard applies, and everything written later -- including the transmit spool
// -- would inherit that. A missing directory therefore surfaces as an error
// here, which applyHeartbeat already degrades into a scan warning: the cost
// is one redundant full send next run, never a wrong report.
func writeHeartbeatState(dir string, perm os.FileMode, state heartbeatState) error {
	target := filepath.Join(dir, heartbeatStateFile)
	return output.AtomicWriteFile(target, perm, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(state)
	})
}

// applyHeartbeat decides whether this scan sends its components, and records
// the decision on the report.
//
// Three things force a full send, and each exists because the alternative is a
// change that never arrives:
//
//   - the digest differs from the previous scan, which is the point;
//   - --force-full, for an operator who has reason to distrust the state;
//   - nothing has been sent in full for longer than --full-interval, so that a
//     digest collision, a hand-edited state file or a bug cannot hide a change
//     indefinitely. A day of staleness is recoverable; an indefinite one is
//     not.
func applyHeartbeat(cfg *config, report *model.Report, logf func(string, ...any)) {
	if !cfg.heartbeat && cfg.transmit == "" {
		return
	}

	digest := model.InventoryDigest(report.Components)
	report.Scan.InventoryDigest = digest

	// --transmit computes the digest but does not suppress anything. The
	// manifest record is what the server opens a scan with and reconciles
	// against, so it has to exist on every transmitted stream; the volume
	// reduction is a separate decision the operator makes with --heartbeat.
	if !cfg.heartbeat {
		return
	}

	host := report.Host.Hostname
	if host == "" {
		host = "unknown-host"
	}
	state := readHeartbeatState(cfg.out)
	previous, known := state.Hosts[host]

	now := report.Scan.StartedAt
	var reason string
	switch {
	case cfg.forceFull:
		reason = "--force-full"
	case !known:
		reason = "no previous scan is recorded for this host"
	case previous.Digest != digest:
		reason = "the inventory changed"
	case cfg.fullInterval > 0 && now.Sub(previous.FullAt) >= cfg.fullInterval:
		reason = fmt.Sprintf("nothing has been sent in full for %s", cfg.fullInterval)
	}

	if reason == "" {
		report.Scan.InventoryUnchanged = true
		logf("heartbeat: inventory unchanged (%s); NDJSON carries the heartbeat only", short(digest))
		// The digest is unchanged, so the recorded one already matches and the
		// full-send clock must keep running from when a full list was actually
		// sent. Nothing to write.
		return
	}

	logf("heartbeat: sending the full component list: %s", reason)
	state.Hosts[host] = heartbeatHost{Digest: digest, FullAt: now}
	if err := writeHeartbeatState(cfg.out, cfg.filePerm, state); err != nil {
		// Not fatal. The report is correct either way; the cost is that the
		// next scan cannot tell it is unchanged and sends everything again.
		report.Scan.AddWarning("could not record the heartbeat digest, so the next scan will send a full component list: " + err.Error())
	}
}

// short abbreviates a digest for a log line.
func short(digest string) string {
	if len(digest) > 19 {
		return digest[:19] + "…"
	}
	return digest
}
