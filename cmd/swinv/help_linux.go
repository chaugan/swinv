//go:build !windows

package main

// The opening paragraph answers the question a new operator actually has,
// which is not "what is this" but "what will it do to this machine if I run
// it and walk away". Everything else in the page is an index; this is the part
// worth reading.
const helpHeader = `swinv - local software inventory collector

Usage:
  swinv [flags]                 (takes no positional arguments)

With no flags, swinv scans / - but not /home, and not network or virtual
filesystems - and writes JSON and CSV into /var/lib/swinv. It runs at
background priority, deliberately slower than it could be; --fast trades that
for speed. The only network activity is a reverse-DNS lookup, which --offline
disables. No inventory data leaves this machine unless --transmit says so.
`

func helpSections() []helpSection {
	return []helpSection{
		{"Output", []helpFlag{
			{"--out DIR", "output directory (default /var/lib/swinv)"},
			{"--format LIST", "json,csv,ndjson,cyclonedx-json (default json,csv)"},
			{"--stdout", "write to stdout (needs exactly one --format)"},
			{"--output-mode MODE", "new file per run (default); or dated, overwrite"},
			{"--name TEMPLATE", "name template: {hostname} {date} {datetime}"},
			{"--latest-symlink", "keep <host>-latest.<ext> (=false to disable)"},
			{"--perm OCTAL", "report file mode (default 0644)"},
		}},
		{"What gets scanned", []helpFlag{
			{"--root PATH", "scan this tree instead of / (an image, a chroot)"},
			{"--include-home", "also scan /home and /root (skipped by default)"},
			{"--exclude GLOB", "skip a path; repeatable; ./ */ or **/ prefix"},
			{"--no-snap, --no-flatpak", "skip snaps or flatpaks (both included by default)"},
			{"--no-auto-exclude-mounts", "do not skip network and virtual filesystems"},
			{"--skip-nested-rootfs", "drop packages from images or chroots on disk"},
			{"--catalogers EXPR", "e.g. os or +binary,-python; narrows output only"},
			{"--offline", "no network activity at all"},
		}},
		{"What is listening", []helpFlag{
			{"--no-services, --no-containers", "skip listening sockets, or containers"},
			{"--elf-scope MODE", "read shared-library links: listening, all, off"},
			{"--config-scope MODE", "config surface: standard, all, off"},
			{"--elf-symbols", "record imported symbol lists, not only counts"},
			{"--no-service-command", "omit command lines; they can carry passwords"},
		}},
		{"Comparing against a previous run", []helpFlag{
			{"--since, --delta-only", "diff an earlier report; or only what changed"},
			{"--hash", "record a SHA-256 per component"},
			{"--ndjson-include LIST", "NDJSON also carries: exposure, containers, links, all"},
			{"--heartbeat", "a digest per scan, components only on change"},
			{"--force-full, --full-interval", "send in full anyway, or at least this often"},
		}},
		{"Transmitting to a server", []helpFlag{
			{"--transmit URL", "also POST this scan; the files are still written"},
			{"--transmit-token-file F", "bearer token file, or $SWINV_TRANSMIT_TOKEN"},
			{"--transmit-cert, --transmit-key, --transmit-ca", "client certificate, its key, and the server's CA"},
			{"--transmit-key-passphrase-file F", "decrypt the key; or systemd credential, or env"},
			{"--transmit-pin SPKI", "pin the server's public key; repeatable"},
			{"--transmit-insecure", "do not verify the server certificate at all"},
			{"--transmit-check", "validate endpoint, auth, TLS and clock, then exit"},
			{"--transmit-only, --transmit-from F", "send the spool, or one NDJSON file; no scan"},
			{"--transmit-require-complete", "=false: send even when a source failed"},
			{"--transmit-batch-lines, --transmit-batch-bytes", "request size; first limit to trip wins"},
			{"--transmit-attempts, --transmit-timeout", "retries, and one request's deadline"},
			{"--transmit-tls-min, --transmit-compress, --transmit-rate-limit", "TLS floor; gzip auto,always,never; cap B/s"},
		}},
		{"Resources", []helpFlag{
			{"--fast", "normal priority, every CPU; fast but intrusive"},
			{"--timeout DURATION", "whole-run deadline (default 30m, then exit 4)"},
			{"--max-memory SIZE", "soft memory limit, e.g. 1536MiB"},
			{"--parallelism N", "cataloger workers (0 = auto)"},
		}},
		{"Diagnostics", []helpFlag{
			{"--verbose, --quiet", "per-stage timing on stderr, or no status at all"},
			{"--debug-stacks-after DUR", "dump goroutine stacks if still running"},
			{"--require-host-id", "fail if /etc/machine-id cannot be read"},
			{"--no-file-ownership", "skip file ownership; faster, more duplicates"},
			{"--version", "print version and exit"},
		}},
	}
}

const helpFooter = `
Examples:
  swinv --out /var/lib/swinv
        Inventory this host into JSON and CSV.

  swinv --out /var/lib/swinv --since /var/lib/swinv/myhost-latest.json
        Report what changed since the previous run.

  swinv --format cyclonedx-json --stdout | grype
        Pipe an SBOM straight into a vulnerability scanner.

  sudo swinv --out /var/lib/swinv
        As root, also identify what is listening and which installed package
        each listener came from. Unprivileged, the ports are still reported
        but the processes behind them mostly are not.

Exit codes:
  0 complete       1 incomplete      2 usage error     3 failed
  4 timed out      5 source unreadable                 6 transmit failed

Exit 5 means a package database is present and unreadable, so the inventory is
short by an unknown amount - which looks exactly like a healthy minimal host.

See also:
  man 8 swinv                   full reference, on this machine
  docs/FLAGS.md                 canonical semantics and worked recipes

--full-scan, --usn-probe and --volumes are Windows-only. This binary accepts
them and refuses with an explanation.
`
