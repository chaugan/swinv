//go:build windows

package main

// The Windows opening paragraph is a different document, not a translation.
// The default here reads the uninstall registry rather than walking a
// filesystem, and the gap between "nothing else is installed" and "nothing
// else was looked for" is the whole completeness question on this platform --
// so --full-scan is named in the first paragraph rather than buried in a list.
const helpHeader = `swinv — local software inventory collector

Usage:
  swinv [flags]                 (takes no positional arguments)

With no flags, swinv reads the Windows uninstall registry — the same records
behind Add/Remove Programs — and writes JSON and CSV into the output
directory. That takes milliseconds and opens no files, but it only sees
software that registers an uninstall entry. Pass --full-scan to also enumerate
executables on disk and read their versions, which takes minutes. It runs at
background priority; --fast trades that for speed. No inventory data leaves
the machine.
`

func helpSections() []helpSection {
	return []helpSection{
		{"Output", []helpFlag{
			{"--out DIR", "where reports are written"},
			{"--format LIST", "json, csv, ndjson, cyclonedx-json (default json,csv)"},
			{"--stdout", "write the report to stdout; needs exactly one --format"},
			{"--output-mode MODE", "how files accumulate: dated, overwrite, timestamped (default dated)"},
			{"--name TEMPLATE", "report file name; {hostname} {machine_id} {date} {datetime}"},
			{"--latest-symlink", "maintain <host>-latest.<ext> (default true; off with --latest-symlink=false)"},
			{"--perm OCTAL", "permission bits for the reports (default 0644)"},
		}},
		{"What gets scanned", []helpFlag{
			{"--full-scan", "also enumerate executables on disk and extract their versions; finds software the registry does not record, and takes minutes rather than milliseconds"},
			{"--volumes LIST", "volumes to enumerate with --full-scan, e.g. D: or D:,E:; replaces the default of C: rather than adding to it"},
			{"--exclude GLOB", "skip a path; repeatable; must start with ./ or */ or **/"},
			{"--catalogers EXPR", "select catalogers, e.g. os or +binary,-python"},
			{"--offline", "no network activity at all, including the FQDN lookup"},
		}},
		{"Comparing against a previous run", []helpFlag{
			{"--since PATH", "diff against an earlier swinv JSON report"},
			{"--delta-only", "with --since, emit only what changed"},
			{"--hash", "record a SHA-256 of each component's primary file"},
		}},
		{"Resources", []helpFlag{
			{"--fast", "run at normal priority using every CPU; faster, but competes with everything else on the machine"},
			{"--timeout DURATION", "whole-run deadline (default 30m; exceeding it exits 4)"},
			{"--max-memory SIZE", "soft memory limit, e.g. 1536MiB"},
			{"--parallelism N", "workers used to read executables (0 = a quarter of the CPUs, or all with --fast)"},
		}},
		{"Diagnostics", []helpFlag{
			{"--verbose", "per-stage timing on stderr"},
			{"--quiet", "no status output at all; errors are still reported"},
			{"--debug-stacks-after DUR", "dump every goroutine stack to a file if the scan is still running, for investigating one that appears hung"},
			{"--usn-probe", "report what the Master File Table contains and exit, without collecting an inventory; a measuring instrument, not a scan"},
			{"--no-file-ownership", "skip package-file ownership; faster, but reintroduces duplicates"},
			{"--version", "print version, commit and Syft version, then exit"},
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

  swinv --out C:\inventory --since C:\inventory\myhost-latest.json
        Report what changed since the previous run.

Exit codes:
  0 complete    1 incomplete    2 usage error    3 failed    4 timed out

See also:
  docs\FLAGS.md                 canonical semantics and worked recipes
  docs\WINDOWS.md               what Windows support does and does not cover

--full-scan and --usn-probe need an elevated process and an NTFS volume, and
say so if they do not have one.
`
