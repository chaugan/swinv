package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

const usageText = `swinv — local software inventory collector

Usage:
  swinv [flags]

Scans this machine, enumerates installed software (OS packages, language
packages, and loose binaries), and writes the result to local files.
Nothing is ever sent over the network.

Flags:
`

// parseFlags builds a config from argv.
//
// It returns (nil, code, nil) when the caller should exit immediately without
// scanning — that is, for -h. A non-nil error means a usage problem.
func parseFlags(args []string, stderr io.Writer) (*config, int, error) {
	cfg := &config{}
	fs := flag.NewFlagSet("swinv", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.StringVar(&cfg.root, "root", "/", "filesystem root to scan")
	fs.StringVar(&cfg.out, "out", "/var/lib/swinv", "output directory")
	fs.StringVar(&cfg.name, "name", "", "output basename template; supports {hostname}, {machine_id}, {date}, {datetime} (default: chosen by --output-mode)")
	fs.StringVar(&cfg.outputMode, "output-mode", modeDated,
		"how output files are named across runs: `dated` (one file per day), overwrite (one fixed file, replaced every run), or timestamped (a new file every run)")
	fs.StringVar(&cfg.format, "format", "json,csv", "comma-separated output formats: json, csv, ndjson, cyclonedx-json")
	fs.BoolVar(&cfg.toStdout, "stdout", false, "write to stdout instead of files; requires exactly one --format")
	fs.BoolVar(&cfg.latestSymlink, "latest-symlink", true, "also maintain {hostname}-latest.{ext} symlinks in --out")
	fs.Var(&cfg.excludes, "exclude", "additional exclusion pattern (repeatable); must start with ./, */ or **/")
	fs.BoolVar(&cfg.noAutoExclude, "no-auto-exclude-mounts", false, "do not auto-exclude non-local filesystems")
	fs.BoolVar(&cfg.noSnap, "no-snap", false, "exclude /snap")
	fs.BoolVar(&cfg.noFlatpak, "no-flatpak", false, "exclude /var/lib/flatpak")
	fs.BoolVar(&cfg.includeHome, "include-home", false, "also scan user home directories (/home and /root); off by default because they dominate scan time and are privacy-sensitive")
	fs.StringVar(&cfg.maxMemory, "max-memory", "", "soft memory limit, e.g. 512MiB or 2GiB; makes the GC work harder near the limit (empty = unlimited)")
	fs.BoolVar(&cfg.noFQDN, "no-fqdn", false, "skip the reverse-DNS lookup for the host FQDN; makes the run perform no network activity whatsoever")
	fs.BoolVar(&cfg.hash, "hash", false, "record a SHA-256 of each component's primary file; useful for change detection and integrity, at the cost of reading every such file")
	fs.StringVar(&cfg.since, "since", "", "path to a previous swinv JSON report; adds a delta of added/removed/changed components")
	fs.BoolVar(&cfg.deltaOnly, "delta-only", false, "with --since, emit only the changed components instead of the full inventory")
	fs.StringVar(&cfg.catalogers, "catalogers", "", "cataloger selection expression, e.g. 'os' or '+binary,-python'")
	fs.BoolVar(&cfg.noFileOwnership, "no-file-ownership", false, "skip package-file ownership (faster, but reintroduces binary/package duplicates)")
	fs.IntVar(&cfg.parallelism, "parallelism", 0, "cataloger parallelism (0 = number of CPUs)")
	fs.DurationVar(&cfg.timeout, "timeout", 30*time.Minute, "whole-run deadline")
	fs.BoolVar(&cfg.requireHostID, "require-host-id", false, "fail if /etc/machine-id is unreadable")
	fs.BoolVar(&cfg.quiet, "quiet", false, "suppress stderr status output")
	fs.BoolVar(&cfg.verbose, "verbose", false, "per-stage timing to stderr")
	fs.BoolVar(&cfg.showVersion, "version", false, "print version, commit, and Syft version, then exit")

	fs.Usage = func() {
		fmt.Fprint(stderr, usageText)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		// -h/--help is a successful request for help, not a usage error, so it
		// must exit 0 or every `swinv -h` in a script looks like a failure.
		if errors.Is(err, flag.ErrHelp) {
			return nil, exitOK, nil
		}
		// flag has already printed the problem and the usage block.
		return nil, exitUsage, fmt.Errorf("invalid flags")
	}
	if fs.NArg() > 0 {
		return nil, exitUsage, fmt.Errorf("unexpected argument %q (swinv takes no positional arguments)", fs.Arg(0))
	}

	// Record whether --name was set explicitly; it overrides --output-mode.
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "name" {
			cfg.nameSet = true
		}
	})

	// --version short-circuits every other check so it always works.
	if cfg.showVersion {
		return cfg, exitOK, nil
	}

	cfg.outputMode = strings.ToLower(strings.TrimSpace(cfg.outputMode))
	if _, ok := defaultNameTemplates[cfg.outputMode]; !ok {
		return nil, exitUsage, fmt.Errorf("unknown --output-mode %q (want one of: %s)",
			cfg.outputMode, strings.Join(validModes(), ", "))
	}

	if cfg.root == "" {
		return nil, exitUsage, fmt.Errorf("--root must not be empty")
	}
	if cfg.timeout <= 0 {
		return nil, exitUsage, fmt.Errorf("--timeout must be positive, got %s", cfg.timeout)
	}
	if cfg.parallelism < 0 {
		return nil, exitUsage, fmt.Errorf("--parallelism must not be negative, got %d", cfg.parallelism)
	}
	if cfg.quiet && cfg.verbose {
		return nil, exitUsage, fmt.Errorf("--quiet and --verbose are mutually exclusive")
	}
	if cfg.maxMemory != "" {
		n, err := parseSize(cfg.maxMemory)
		if err != nil {
			return nil, exitUsage, fmt.Errorf("--max-memory: %w", err)
		}
		cfg.maxMemoryBytes = n
	}
	if cfg.deltaOnly && cfg.since == "" {
		return nil, exitUsage, fmt.Errorf("--delta-only requires --since")
	}
	if cfg.toStdout && cfg.nameSet {
		return nil, exitUsage, fmt.Errorf("--name has no meaning with --stdout")
	}

	return cfg, exitOK, nil
}
