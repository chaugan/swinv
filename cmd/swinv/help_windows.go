//go:build windows

package main

// The Windows opening paragraph is a different document, not a translation.
// The default here reads the uninstall registry rather than walking a
// filesystem, and the gap between "nothing else is installed" and "nothing
// else was looked for" is the whole completeness question on this platform --
// so --full-scan is named in the first paragraph rather than buried in a list.
const helpHeader = `swinv - local software inventory collector

Usage:
  swinv [flags]                 (takes no positional arguments)

With no flags, swinv reads the Windows uninstall registry - the records behind
Add/Remove Programs - and writes JSON and CSV. That takes milliseconds and
opens no files, but it sees only software that registers an uninstall entry.
--full-scan also reads executables on disk, which takes minutes and needs an
elevated prompt. No inventory data leaves this machine unless --transmit
says so.
`

func helpSections() []helpSection {
	return []helpSection{
		{"Output", []helpFlag{
			{"--out DIR", "output directory"},
			{"--format LIST", "json,csv,ndjson,cyclonedx-json (default json,csv)"},
			{"--stdout", "write to stdout (needs exactly one --format)"},
			{"--output-mode MODE", "new file per run (default); or dated, overwrite"},
			{"--name TEMPLATE", "name template: {hostname} {date} {datetime}"},
			{"--latest-symlink", "keep <host>-latest.<ext> (=false to disable)"},
			{"--html-report PATH, --report-from PATH", "self-contained HTML report; --report-from renders one from a file, no scan"},
			{"--perm OCTAL", "report file mode (default 0644)"},
		}},
		{"What gets scanned", []helpFlag{
			{"--full-scan", "also read executables on disk; finds unregistered software, takes minutes"},
			{"--volumes LIST", "volumes for --full-scan, e.g. D: or D:,E: (replaces C:)"},
			{"--exclude GLOB", "skip a path; repeatable; ./ */ or **/ prefix"},
			{"--catalogers EXPR", "e.g. os or +binary,-python"},
			{"--all-interfaces", "collect all interfaces and their addresses"},
			{"--offline", "no network activity at all"},
		}},
		{"What is listening", []helpFlag{
			{"--no-services, --no-containers", "skip listening sockets, or containers"},
			{"--config-scope MODE", "config surface: standard, all, off"},
			{"--elf-scope MODE", "import tables: listening, all (with --full-scan), off"},
			{"--elf-symbols", "record imported function lists, not only counts"},
			{"--no-service-command", "omit command lines; they can carry passwords"},
		}},
		{"Comparing against a previous run", []helpFlag{
			{"--ndjson-include LIST", "NDJSON also carries: exposure, containers, all"},
			{"--heartbeat", "a digest per scan, components only on change"},
			{"--force-full, --full-interval", "send in full anyway, or at least this often"},
			{"--since, --delta-only", "diff an earlier report; or only what changed"},
			{"--hash", "record a SHA-256 per component"},
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
			{"--parallelism N", "workers reading executables (0 = auto)"},
		}},
		{"Diagnostics", []helpFlag{
			{"--verbose, --quiet", "per-stage timing on stderr, or no status at all"},
			{"--debug-stacks-after DUR", "dump goroutine stacks if still running"},
			{"--usn-probe", "report what the MFT holds and exit; measures only"},
			{"--no-file-ownership", "skip file ownership; faster, more duplicates"},
			{"--version", "print version and exit"},
		}},
	}
}

const helpFooter = `
Examples:
  swinv --out C:\inventory
        Read the uninstall registry. Fast, and needs no elevation.

  swinv --out C:\inventory --full-scan
        Also enumerate executables the registry does not account for.
        Needs an elevated prompt and an NTFS volume.

  swinv --out C:\inventory --full-scan --volumes D:,E:
        Enumerate D: and E: instead of C:.

  swinv --out C:\inventory --no-containers
        Skip asking the Docker engine what it runs.

Exit codes:
  0 complete       1 incomplete      2 usage error     3 failed
  4 timed out      5 source unreadable                 6 transmit failed

Exit 5 means a package database is present and unreadable, so the inventory is
short by an unknown amount - which looks exactly like a healthy minimal host.

See also:
  docs\FLAGS.md                 canonical semantics and worked recipes
  docs\WINDOWS.md               what Windows support does and does not cover

--full-scan and --usn-probe need an elevated process and an NTFS volume, and
say so if they do not have one.
`
