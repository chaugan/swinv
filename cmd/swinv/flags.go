package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// parseFlags builds a config from argv.
//
// It returns (nil, code, nil) when the caller should exit immediately without
// scanning — that is, for -h. A non-nil error means a usage problem.
func parseFlags(args []string, stdout, stderr io.Writer) (*config, int, error) {
	cfg := &config{}
	fs := flag.NewFlagSet("swinv", flag.ContinueOnError)
	fs.SetOutput(stderr)

	registerFlags(fs, cfg)

	// flag calls Usage on -h and on any parse failure. Only the first of those
	// wants the help page: an operator who mistyped a flag needs one line
	// naming it, not sixty lines of everything else. So Usage prints nothing,
	// and the two cases are handled separately below.
	fs.Usage = func() {}

	if err := fs.Parse(args); err != nil {
		// -h/--help is a successful request for help, not a usage error, so it
		// exits 0 -- otherwise every `swinv -h` in a script looks like a
		// failure -- and it prints to stdout, so `swinv --help | less` is not
		// an empty pager.
		if errors.Is(err, flag.ErrHelp) {
			writeHelp(stdout)
			return nil, exitOK, nil
		}
		// flag has already printed its own one-line complaint to stderr.
		return nil, exitUsage, errors.New("try 'swinv --help' for the available flags")
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
	filePerm, err := parsePerm(cfg.perm)
	if err != nil {
		return nil, exitUsage, fmt.Errorf("--perm: %w", err)
	}
	cfg.filePerm = filePerm
	cfg.dirPerm = dirPermFor(filePerm)

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

// parsePerm converts an octal permission string such as "0640" or "600" into
// file mode bits.
//
// Only the nine permission bits are accepted. Setuid, setgid and the sticky bit
// are refused rather than silently dropped: an inventory file has no business
// carrying them, and quietly ignoring what the operator asked for would be
// worse than saying no.
func parsePerm(s string) (os.FileMode, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return 0, fmt.Errorf("empty permission")
	}
	v, err := strconv.ParseUint(raw, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid octal permission %q (want something like 0644 or 0600)", s)
	}
	if v > 0o777 {
		return 0, fmt.Errorf("permission %q is out of range; only the nine rwx bits are accepted, "+
			"so setuid, setgid and the sticky bit cannot be set", s)
	}
	if v&0o400 == 0 {
		return 0, fmt.Errorf("permission %q would make the report unreadable by its own owner", s)
	}
	return os.FileMode(v), nil
}

// dirPermFor derives the output directory's mode from the report file mode: a
// directory needs the execute bit wherever the file grants read, or the files
// inside it cannot be reached. 0644 gives 0755, 0640 gives 0750, 0600 gives
// 0700. The owner always keeps write and execute so swinv can create the files
// at all.
func dirPermFor(file os.FileMode) os.FileMode {
	dir := file
	for _, shift := range []uint{6, 3, 0} {
		if dir&(0o4<<shift) != 0 {
			dir |= 0o1 << shift
		}
	}
	return dir | 0o300
}

// registerFlags declares every flag on fs.
//
// Split out of parseFlags so that the help test can enumerate what actually
// exists and compare it against what the help page claims. Help is a user
// interface, and until this existed nothing checked it: a 203-character
// description and three Windows-only flags shown on Linux both survived
// review because no test looked.
func registerFlags(fs *flag.FlagSet, cfg *config) {
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
	fs.BoolVar(&cfg.offline, "offline", false, "perform no network activity at all; skips the reverse-DNS lookup that fills host.fqdn, which is the only thing swinv uses the network for")
	fs.BoolVar(&cfg.skipNestedRootfs, "skip-nested-rootfs", false, "drop components that exist only because the scan walked into a second root filesystem (an extracted image, a container rootfs, a chroot); off by default because scanning those is sometimes the point")
	fs.StringVar(&cfg.perm, "perm", "0644", "octal permission bits for the report files; the output directory gets the same bits plus execute wherever read is granted (0644 -> 0755, 0640 -> 0750, 0600 -> 0700)")
	fs.BoolVar(&cfg.hash, "hash", false, "record a SHA-256 of each component's primary file; useful for change detection and integrity, at the cost of reading every such file")
	fs.StringVar(&cfg.since, "since", "", "path to a previous swinv JSON report; adds a delta of added/removed/changed components")
	fs.BoolVar(&cfg.deltaOnly, "delta-only", false, "with --since, emit only the changed components instead of the full inventory")
	fs.StringVar(&cfg.catalogers, "catalogers", "", "cataloger selection expression, e.g. 'os' or '+binary,-python'")
	fs.BoolVar(&cfg.noFileOwnership, "no-file-ownership", false, "skip package-file ownership (faster, but reintroduces binary/package duplicates)")
	fs.IntVar(&cfg.parallelism, "parallelism", 0, "cataloger parallelism (0 = automatic: a quarter of the CPUs, or all of them with --fast)")
	fs.BoolVar(&cfg.fullScan, "full-scan", false, "Windows only: also enumerate the filesystem and extract versions from executables the registry does not account for")
	fs.BoolVar(&cfg.usnProbe, "usn-probe", false, "Windows only, experimental: enumerate the NTFS Master File Table and report what it finds, without scanning; see docs/WINDOWS.md")
	fs.StringVar(&cfg.volumes, "volumes", "", "Windows only: comma-separated volumes to enumerate, e.g. \"D:\" or \"D:,E:\". Replaces the default of C: rather than adding to it")
	fs.DurationVar(&cfg.stacksAfter, "debug-stacks-after", 0, "if a scan is still running after this long, write every goroutine stack to a file in the output directory and carry on (0 = never); for diagnosing a scan that appears hung")
	fs.BoolVar(&cfg.fast, "fast", false, "scan at normal scheduling priority and full parallelism; faster, but the scan competes with everything else on the machine")
	fs.DurationVar(&cfg.timeout, "timeout", 30*time.Minute, "whole-run deadline")
	fs.BoolVar(&cfg.requireHostID, "require-host-id", false, "fail if /etc/machine-id is unreadable")
	fs.BoolVar(&cfg.quiet, "quiet", false, "suppress stderr status output")
	fs.BoolVar(&cfg.verbose, "verbose", false, "per-stage timing to stderr")
	fs.BoolVar(&cfg.showVersion, "version", false, "print version, commit, and Syft version, then exit")
}
