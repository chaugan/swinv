package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/chaugan/swinv/internal/transmit"
)

// This file is the two run modes that talk to the server without scanning.
//
// --transmit-check exists because diagnosing a broken deployment by running a
// full scan is a thirty-minute way to learn the token was wrong. The other
// two flags cover the outage story: the server was down, the spool holds
// scans, and the only way to flush it should not be another scan per host.

// runTransmitCheck validates the deployment and exits.
func runTransmitCheck(cfg *config, logf func(string, ...any), stdout, stderr io.Writer) int {
	client, err := newTransmitClient(cfg, logf)
	if err != nil {
		fmt.Fprintf(stderr, "swinv: %v\n", err)
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), transmitDeadline(cfg))
	defer cancel()

	code := exitOK
	for _, r := range client.Check(ctx) {
		state := "ok  "
		if !r.OK {
			state = "FAIL"
			code = exitTransmit
		}
		// One check per line, greppable, to stdout: this output is the
		// answer the operator asked for, not status about something else.
		fmt.Fprintf(stdout, "%s  %-16s %s\n", state, r.Name, r.Detail)
	}
	return code
}

// runTransmitSend sends without scanning: the spooled backlog, and with
// --transmit-from also one existing NDJSON file.
func runTransmitSend(cfg *config, logf func(string, ...any), stderr io.Writer) int {
	client, err := newTransmitClient(cfg, logf)
	if err != nil {
		fmt.Fprintf(stderr, "swinv: %v\n", err)
		return exitUsage
	}
	dir := spoolDir(cfg)

	backlog, err := transmit.Pending(dir, client.Endpoint())
	if err != nil {
		fmt.Fprintf(stderr, "swinv: warning: %v\n", err)
	}
	if all, err := transmit.Pending(dir, ""); err == nil && len(all) > len(backlog) {
		fmt.Fprintf(stderr, "swinv: warning: %d spooled scan(s) in %s were collected for a "+
			"different server and will not be sent; delete them or point --transmit back\n",
			len(all)-len(backlog), dir)
	}

	queue := backlog
	if cfg.transmitFrom != "" {
		sp, err := spoolFromFile(cfg, client, dir)
		if err != nil {
			fmt.Fprintf(stderr, "swinv: --transmit-from: %v\n", err)
			return exitUsage
		}
		queue = append(queue, sp)
	}
	if len(queue) == 0 {
		logf("transmit: the spool at %s is empty; nothing to send", dir)
		return exitOK
	}

	ctx, cancel := context.WithTimeout(context.Background(), transmitDeadline(cfg))
	defer cancel()
	worst := exitOK
	for _, sp := range queue {
		if code := sendOne(ctx, client, sp, logf, stderr); code != exitOK {
			worst = code
		}
	}
	return worst
}

// spoolFromFile validates an existing NDJSON file and spools it for sending.
//
// The validation is the same contract the server enforces: the first line
// must be the manifest, and its counts must agree with the records that
// follow. Refusing here beats uploading a file already known to be broken -
// the server's 409 would be correct and useless, since the operator holding
// the file is the only one who can fix it.
func spoolFromFile(cfg *config, client *transmit.Client, dir string) (*transmit.Spool, error) {
	f, err := os.Open(cfg.transmitFrom) // #nosec G304 -- operator-supplied path, by design
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	manifest, counted, err := readNDJSONManifest(f)
	if err != nil {
		return nil, err
	}
	for kind, want := range manifest.Counts {
		if got := counted[kind]; got != want {
			return nil, fmt.Errorf("%s declares %d %s record(s) and holds %d; "+
				"refusing to upload a file that is already known to be wrong",
				cfg.transmitFrom, want, kind, got)
		}
	}
	for kind, got := range counted {
		if _, declared := manifest.Counts[kind]; !declared && got != 0 {
			return nil, fmt.Errorf("%s holds %d %s record(s) its manifest never declared",
				cfg.transmitFrom, got, kind)
		}
	}

	return client.NewSpool(dir, manifest.ScanID, manifest.Hostname,
		manifest.Counts["component"], cfg.filePerm, cfg.dirPerm,
		func(w io.Writer) error {
			src, err := os.Open(cfg.transmitFrom) // #nosec G304 -- validated just above
			if err != nil {
				return err
			}
			defer func() { _ = src.Close() }()
			_, err = io.Copy(w, src)
			return err
		})
}

// ndjsonManifest is the slice of the heartbeat line this validation needs.
type ndjsonManifest struct {
	RecordType string         `json:"record_type"`
	ScanID     string         `json:"scan_id"`
	Hostname   string         `json:"hostname"`
	Counts     map[string]int `json:"counts"`
}

// readNDJSONManifest reads the manifest line and tallies the records after it
// the way a receiver would: a line with no record_type is a component.
func readNDJSONManifest(r io.Reader) (*ndjsonManifest, map[string]int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	if !sc.Scan() {
		return nil, nil, fmt.Errorf("the file is empty")
	}
	var m ndjsonManifest
	if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
		return nil, nil, fmt.Errorf("line 1 is not JSON: %w", err)
	}
	if m.RecordType != "heartbeat" || m.Counts == nil {
		return nil, nil, fmt.Errorf("line 1 is not a manifest; only a scan written with " +
			"--heartbeat or --transmit carries one, and a file without one cannot be verified before upload")
	}
	counted := map[string]int{}
	line := 1
	for sc.Scan() {
		line++
		var rec struct {
			RecordType string `json:"record_type"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return nil, nil, fmt.Errorf("line %d is not JSON: %w", line, err)
		}
		kind := rec.RecordType
		if kind == "" {
			kind = "component"
		}
		counted[kind]++
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	// The manifest line itself is not a record it declares.
	delete(counted, "heartbeat")
	return &m, counted, nil
}
