package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/output"
	"github.com/chaugan/swinv/internal/transmit"
)

// transmitTokenEnv is where a bearer token belongs when it is not in a file.
//
// There is deliberately no --transmit-token flag. Every process on the machine
// can read /proc/<pid>/cmdline, so a token on the command line is a token
// handed to every local user, and a systemd unit's ExecStart is world-readable
// in the journal besides.
// #nosec G101 -- this is the name of an environment variable, not a token
const transmitTokenEnv = "SWINV_TRANSMIT_TOKEN"

// transmitToken resolves the bearer token from its file or the environment.
func transmitToken(cfg *config) (string, error) {
	if cfg.transmitTokenFile != "" {
		raw, err := os.ReadFile(cfg.transmitTokenFile) // #nosec G304 -- operator-supplied path, by design
		if err != nil {
			return "", fmt.Errorf("--transmit-token-file: %w", err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", fmt.Errorf("--transmit-token-file: %s is empty", cfg.transmitTokenFile)
		}
		return token, nil
	}
	return strings.TrimSpace(os.Getenv(transmitTokenEnv)), nil
}

// newTransmitClient builds the client from the flags.
func newTransmitClient(cfg *config, logf func(string, ...any)) (*transmit.Client, error) {
	token, err := transmitToken(cfg)
	if err != nil {
		return nil, err
	}
	return transmit.New(transmit.Options{
		BaseURL:            cfg.transmit,
		Token:              token,
		ClientCertFile:     cfg.transmitCert,
		ClientKeyFile:      cfg.transmitKey,
		CAFile:             cfg.transmitCA,
		InsecureSkipVerify: cfg.transmitInsecure,
		BatchLines:         cfg.transmitBatchLines,
		BatchBytes:         int(cfg.transmitBatchBytesN),
		Attempts:           cfg.transmitAttempts,
		RequestTimeout:     cfg.transmitTimeout,
		Logf:               logf,
	})
}

// spoolDir is where scans wait to be uploaded.
func spoolDir(cfg *config) string {
	return filepath.Join(cfg.out, transmit.SpoolDirName)
}

// transmitReport spools this scan and uploads it, along with anything an
// earlier run left behind.
//
// The spool is not an implementation detail of retrying. It is what makes
// resumption real: the bytes that were declared are on disk, so a collector
// that dies at batch nine is finished by the next run rather than starting a
// new scan whose counts no longer match the manifest the server already holds.
func transmitReport(ctx context.Context, cfg *config, report *model.Report, logf func(string, ...any), stderr io.Writer) int {
	client, err := newTransmitClient(cfg, logf)
	if err != nil {
		fmt.Fprintf(stderr, "swinv: %v\n", err)
		return exitUsage
	}

	dir := spoolDir(cfg)

	// The backlog first, oldest first. A host that was offline reports its
	// history in order instead of overwriting it with the newest scan.
	//
	// Matched to this endpoint, because a spool records the server it was
	// collected for: re-pointing --transmit is a deliberate act, and quietly
	// delivering the old server's queue to the new one would post an estate's
	// inventory somewhere nobody chose to send it.
	backlog, err := transmit.Pending(dir, client.Endpoint())
	if err != nil {
		// Named, not fatal: an unreadable state file must not stop the scan
		// that just completed from reaching the server.
		fmt.Fprintf(stderr, "swinv: warning: %v\n", err)
	}
	if all, err := transmit.Pending(dir, ""); err == nil && len(all) > len(backlog) {
		// Said out loud, because a spool directory silently filling with
		// undeliverable scans is exactly the sort of thing nobody notices
		// until the disk is full.
		fmt.Fprintf(stderr, "swinv: warning: %d spooled scan(s) in %s were collected for a "+
			"different server and will not be sent; delete them or point --transmit back\n",
			len(all)-len(backlog), dir)
	}

	declared, _ := manifestDeclaredComponents(report)
	fresh, err := client.NewSpool(dir, report.Scan.ScanID, report.Host.Hostname, declared,
		cfg.filePerm, cfg.dirPerm, func(w io.Writer) error {
			return output.WriteNDJSON(w, report)
		})
	if err != nil {
		fmt.Fprintf(stderr, "swinv: %v\n", err)
		return exitTransmit
	}

	worst := exitOK
	for _, sp := range append(backlog, fresh) {
		if code := sendOne(ctx, client, sp, logf, stderr); code != exitOK {
			worst = code
		}
	}
	return worst
}

// sendOne uploads one spooled scan and decides what its outcome means.
func sendOne(ctx context.Context, client *transmit.Client, sp *transmit.Spool, logf func(string, ...any), stderr io.Writer) int {
	st := sp.State()

	// What the payload really holds, counted from the file about to be sent.
	// The manifest's own number is checked against this before a byte leaves
	// the machine, because a manifest that disagrees with its payload turns
	// the server's reconciliation into a false alarm that nobody can act on.
	records, err := sp.Records()
	if err != nil {
		fmt.Fprintf(stderr, "swinv: %v\n", err)
		return exitTransmit
	}

	verdict, err := client.Send(ctx, sp)
	if err != nil {
		if transmit.IsPermanent(err) {
			// Permanent means retrying changes nothing: a rejected token, a
			// refused certificate, a body the server will not parse, or a
			// count it disagrees with. Say so plainly and leave the spool in
			// place -- the data is still on disk and the operator can fix the
			// cause and run again.
			fmt.Fprintf(stderr, "swinv: transmit failed permanently for scan %s: %v\n", st.ScanID, err)
			fmt.Fprintf(stderr, "swinv: the scan is kept at %s and will be retried on the next run\n",
				sp.PayloadPath())
			return exitTransmit
		}
		fmt.Fprintf(stderr, "swinv: transmit did not complete for scan %s: %v\n", st.ScanID, err)
		fmt.Fprintf(stderr, "swinv: %d of %d record(s) are still queued at %s\n",
			records, records, sp.PayloadPath())
		return exitTransmit
	}

	if !verdict.Reconciled || verdict.Declared != verdict.Stored {
		// The server accepted the upload and its own count disagrees with the
		// manifest. This is the §5 incident caught at the only place it can be
		// caught cheaply, and it is an error rather than a log line for the
		// reason a warning field is: nobody reads warning fields.
		fmt.Fprintf(stderr,
			"swinv: the server stored %d component(s) for scan %s but the manifest declared %d: %s\n",
			verdict.Stored, st.ScanID, verdict.Declared, verdict.Message)
		return exitTransmit
	}

	logf("transmit: scan %s accepted and reconciled (%d component(s))", st.ScanID, verdict.Stored)
	if err := sp.Done(); err != nil {
		// The upload succeeded; failing to tidy up would only re-send an
		// already-reconciled scan, which the server deduplicates.
		fmt.Fprintf(stderr, "swinv: warning: %v\n", err)
	}
	return exitOK
}

// manifestDeclaredComponents is the component count the manifest will state:
// what this stream carries, which is zero when --heartbeat suppressed the
// component records.
func manifestDeclaredComponents(report *model.Report) (int, bool) {
	if report.Scan.InventoryUnchanged {
		return 0, true
	}
	return len(report.Components), false
}

// transmitDeadline bounds the upload separately from the scan.
//
// --timeout is the scan's deadline and is normally already spent by the time
// anything is uploaded. Sharing it would mean a scan that finished at 29m59s
// had one second to reach the server, which is how a slow host stops reporting
// entirely while its logs say "timed out" about the wrong thing.
func transmitDeadline(cfg *config) time.Duration {
	if cfg.transmitTimeout <= 0 {
		return transmit.DefaultRequestTimeout * 10
	}
	return cfg.transmitTimeout * 10
}
