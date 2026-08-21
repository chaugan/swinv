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

With no flags, swinv reads the Windows uninstall registry — the records behind
Add/Remove Programs — and writes JSON and CSV. That takes milliseconds and
opens no files, but it sees only software that registers an uninstall entry.
--full-scan also reads executables on disk, which takes minutes and needs an
elevated prompt. No inventory data leaves this machine.
`

func helpSections() []helpSection {
	return []helpSection{
		{"Output", []helpFlag{
			{"--out DIR", "output directory"},
			{"--format LIST", "json,csv,ndjson,cyclonedx-json (default json,csv)"},
			{"--stdout", "write to stdout (needs exactly one --format)"},
			{"--output-mode MODE", "dated | overwrite | timestamped (default dated)"},
			{"--name TEMPLATE", "name template: {hostname} {date} {datetime}"},
			{"--latest-symlink", "keep <host>-latest.<ext> (=false to disable)"},
			{"--perm OCTAL", "report file mode (default 0644)"},
		}},
		{"What gets scanned", []helpFlag{
			{"--full-scan", "also read executables on disk; finds unregistered software, takes minutes"},
			{"--volumes LIST", "volumes for --full-scan, e.g. D: or D:,E: (replaces C:)"},
			{"--exclude GLOB", "skip a path; repeatable; ./ */ or **/ prefix"},
			{"--catalogers EXPR", "e.g. os or +binary,-python"},
			{"--offline", "no network activity at all"},
		}},
		{"Comparing against a previous run", []helpFlag{
			{"--since PATH", "diff against an earlier swinv JSON report"},
			{"--delta-only", "with --since, emit only what changed"},
			{"--hash", "record a SHA-256 per component"},
		}},
		{"Resources", []helpFlag{
			{"--fast", "normal priority, every CPU; fast but intrusive"},
			{"--timeout DURATION", "whole-run deadline (default 30m, then exit 4)"},
			{"--max-memory SIZE", "soft memory limit, e.g. 1536MiB"},
			{"--parallelism N", "workers reading executables (0 = auto)"},
		}},
		{"Diagnostics", []helpFlag{
			{"--verbose", "per-stage timing on stderr"},
			{"--quiet", "no status output; errors still reported"},
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

Exit codes:
  0 complete    1 incomplete    2 usage error    3 failed    4 timed out

See also:
  docs\FLAGS.md                 canonical semantics and worked recipes
  docs\WINDOWS.md               what Windows support does and does not cover

--full-scan and --usn-probe need an elevated process and an NTFS volume, and
say so if they do not have one.
`
