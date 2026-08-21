// Command swinv scans the local machine, enumerates installed software, and
// writes the inventory to local JSON and CSV files.
//
// It never transmits anything over the network. Files land on disk; collecting
// them afterwards is somebody else's job.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/chaugan/swinv/internal/hostfacts"
	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/output"
	"github.com/chaugan/swinv/internal/privilege"
	"github.com/chaugan/swinv/internal/scan"
	"github.com/chaugan/swinv/internal/sched"
	"github.com/chaugan/swinv/internal/usn"
)

// Build-time values, injected with -ldflags by the Makefile.
var (
	version = "dev"
	commit  = "none"
)

// resolveVersion reports the version to display.
//
// `go install github.com/chaugan/swinv/cmd/swinv@v0.1.1` runs no -ldflags, so
// the stamped value stays "dev" and the binary cannot say what it is. Go does
// record the module version in the build info for that install path, so fall
// back to it. A local `go build` reports "(devel)" there, which is no better
// than "dev", so it is ignored.
func resolveVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return version
}

// Exit codes, per the spec.
const (
	exitOK         = 0 // complete inventory written
	exitIncomplete = 1 // output written, but a cataloger failed
	exitUsage      = 2 // bad flag, bad pattern, conflicting options
	exitFatal      = 3 // could not construct the source or write output
	exitTimeout    = 4 // whole-run deadline exceeded
)

// Output-mode names. The mode picks the default --name template; an explicit
// --name always wins.
const (
	modeDated       = "dated"
	modeOverwrite   = "overwrite"
	modeTimestamped = "timestamped"
)

// defaultNameTemplates maps an --output-mode to the --name template it implies.
var defaultNameTemplates = map[string]string{
	modeDated:       "{hostname}-{date}",
	modeOverwrite:   "{hostname}",
	modeTimestamped: "{hostname}-{datetime}",
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// config holds every flag value, so run stays testable.
type config struct {
	root             string
	out              string
	name             string
	outputMode       string
	format           string
	toStdout         bool
	latestSymlink    bool
	excludes         stringList
	noAutoExclude    bool
	noSnap           bool
	noFlatpak        bool
	includeHome      bool
	hash             bool
	offline          bool
	skipNestedRootfs bool
	perm             string
	filePerm         os.FileMode
	dirPerm          os.FileMode
	maxMemory        string
	maxMemoryBytes   int64
	since            string
	deltaOnly        bool
	catalogers       string
	noFileOwnership  bool
	parallelism      int
	fast             bool
	stacksAfter      time.Duration
	usnProbe         bool
	fullScan         bool
	volumes          string
	timeout          time.Duration
	requireHostID    bool
	quiet            bool
	verbose          bool
	showVersion      bool

	nameSet bool // whether --name was given explicitly
}

// stringList collects a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, code, err := parseFlags(args, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "swinv: %v\n", err)
		return code
	}
	if cfg == nil {
		// --version or -h already handled.
		return code
	}

	logf := func(format string, a ...any) {
		if !cfg.quiet {
			fmt.Fprintf(stderr, "swinv: "+format+"\n", a...)
		}
	}

	if cfg.showVersion {
		fmt.Fprintf(stdout, "swinv %s (commit %s, syft %s, %s/%s)\n",
			resolveVersion(), commit, scan.SyftVersion(), runtime.GOOS, runtime.GOARCH)
		return exitOK
	}

	// --usn-probe short-circuits: it measures a volume rather than producing
	// an inventory, so none of the output, delta or host-facts machinery below
	// applies to it.
	if cfg.usnProbe {
		volumes, err := usn.ParseVolumes(cfg.volumes)
		if err != nil {
			fmt.Fprintf(stderr, "swinv: %v\n", err)
			return exitUsage
		}
		// Its own context: the probe runs before the scan pipeline is set up,
		// but --timeout should still bound it. Enumerating a large volume is
		// not instant, and an operator who asked for a deadline meant it.
		probeCtx, cancelProbe := context.WithTimeout(context.Background(), cfg.timeout)
		defer cancelProbe()
		return runUSNProbe(probeCtx, volumes, stderr, logf)
	}

	if strings.TrimSpace(cfg.volumes) != "" {
		fmt.Fprintln(stderr, "swinv: --volumes currently only applies to --usn-probe; "+
			"the Windows collector it will configure does not exist yet (see docs/WINDOWS.md)")
		return exitUsage
	}

	if cfg.maxMemoryBytes > 0 {
		applyMemoryLimit(cfg.maxMemoryBytes)
		logf("soft memory limit set to %s (the GC will work harder near it; it is not a hard cap)", cfg.maxMemory)
	}

	formats, err := parseFormats(cfg.format, cfg.toStdout)
	if err != nil {
		fmt.Fprintf(stderr, "swinv: %v\n", err)
		return exitUsage
	}

	// Load the --since baseline up front. Validating it only after the scan
	// means a typo in the path costs a full multi-minute scan before the
	// error appears.
	var baseline *model.Report
	if cfg.since != "" {
		var err error
		baseline, err = loadBaseline(cfg.since)
		if err != nil {
			fmt.Fprintf(stderr, "swinv: --since: %v\n", err)
			return exitUsage
		}
	}

	startedAt := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	// --- host facts -------------------------------------------------------
	// --offline is an intent ("touch no network"); hostfacts states the
	// mechanism ("skip the FQDN lookup"). Keeping the two layers separate means
	// a future network-touching feature is disabled by the same flag without
	// renaming anything.
	var hostOpts []hostfacts.Option
	if cfg.offline {
		hostOpts = append(hostOpts, hostfacts.WithoutFQDN())
	}
	host := hostfacts.Collect(ctx, cfg.root, hostOpts...)
	if cfg.requireHostID && host.MachineID == "" {
		fmt.Fprintln(stderr, "swinv: --require-host-id given but /etc/machine-id is empty or unreadable")
		return exitFatal
	}

	priv := privilege.Check()

	meta := model.ScanMeta{
		StartedAt: startedAt,
		Root:      cfg.root,
		RanAsRoot: priv.Elevated,
	}
	if priv.Warning != "" {
		meta.AddWarning(priv.Warning)
	}

	// --- exclusions -------------------------------------------------------
	// Skipped where the inventory does not come from walking the filesystem.
	// On Windows this would otherwise compute two dozen Linux layout
	// exclusions -- /proc, /sys, /home -- and record them in the report as
	// though they had been applied to something.
	var patterns []string
	if !platformHandlesScan() {
		patterns, err = buildExcludes(cfg, &meta, stderr)
		if err != nil {
			return exitUsage
		}
	}

	if cfg.verbose {
		logf("excluding %d path patterns", len(patterns))
	}

	// --- scheduling priority ----------------------------------------------
	// Applied before the scan rather than at startup so that argument parsing,
	// --version and --help are unaffected: only the part that actually costs
	// the machine something runs at a lower priority.
	mode := sched.Background
	if cfg.fast {
		mode = sched.Normal
	}
	schedNotes, schedWarnings := sched.Apply(mode)
	for _, w := range schedWarnings {
		logf("%s", w)
	}
	if cfg.verbose {
		for _, n := range schedNotes {
			logf("%s", n)
		}
	}

	parallelism := resolveParallelism(cfg.parallelism, cfg.fast)
	if cfg.verbose {
		logf("cataloger parallelism %d of %d CPUs", parallelism, runtime.NumCPU())
	}

	// --- scan -------------------------------------------------------------
	logf("scanning %s ...", scanTarget(cfg))
	stopHeartbeat := startHeartbeat(cfg.quiet, cfg.timeout, cfg.stacksAfter, cfg.out, logf)
	stopWatchdog := startDeadlineWatchdog(cfg.timeout, watchdogGrace, stderr)
	result, handled, err := platformScan(ctx, cfg, logf)
	if !handled {
		result, err = scan.Run(ctx, scan.Options{
			Root:             cfg.root,
			Excludes:         patterns,
			CatalogerExpr:    cfg.catalogers,
			FileOwnership:    !cfg.noFileOwnership,
			Parallelism:      parallelism,
			Hash:             cfg.hash,
			SkipNestedRootfs: cfg.skipNestedRootfs,
			Verbose:          cfg.verbose && !cfg.quiet,
		})
	}
	stopWatchdog()
	stopHeartbeat()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintf(stderr, "swinv: timed out after %s\n", cfg.timeout)
			return exitTimeout
		}
		fmt.Fprintf(stderr, "swinv: scan failed: %v\n", err)
		return exitFatal
	}

	meta.FinishedAt = time.Now().UTC()
	meta.DurationMS = meta.FinishedAt.Sub(meta.StartedAt).Milliseconds()
	meta.Catalogers = result.Catalogers
	if len(result.QuarantinedSymlinks) > 0 {
		meta.Excluded = model.SortedSet(append(meta.Excluded, result.QuarantinedSymlinks...))
	}
	meta.Incomplete = result.Incomplete
	for _, w := range result.Warnings {
		meta.AddWarning(w)
	}

	// Syft's distro detection is better than ours when it is populated; fall
	// back to whatever hostfacts read from /etc/os-release.
	if result.Distro != nil {
		if result.Distro.ID != "" {
			host.OSID = result.Distro.ID
		}
		if result.Distro.VersionID != "" {
			host.OSVersionID = result.Distro.VersionID
		}
		if result.Distro.PrettyName != "" {
			host.OSPrettyName = result.Distro.PrettyName
		}
	}
	host.Normalize()

	report := &model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool: model.Tool{
			Name:        "swinv",
			Version:     resolveVersion(),
			Commit:      commit,
			SyftVersion: scan.SyftVersion(),
		},
		Host:       host,
		Scan:       meta,
		Components: model.Normalize(result.Components),
	}

	// --- delta against a previous report ----------------------------------
	if baseline != nil {
		delta := model.ComputeDelta(report.Components, baseline.Components)
		delta.Since = cfg.since
		delta.BaselineAt = baseline.Scan.StartedAt
		delta.BaselineHost = baseline.Host.Hostname

		// Comparing against another machine's inventory produces a delta that
		// looks like a catastrophic change. Say so rather than let it pass.
		if baseline.Host.Hostname != "" && report.Host.Hostname != "" &&
			baseline.Host.Hostname != report.Host.Hostname {
			report.Scan.AddWarning(fmt.Sprintf(
				"--since baseline was taken on %q but this host is %q; the delta compares two different machines",
				baseline.Host.Hostname, report.Host.Hostname))
		}
		report.Delta = delta

		// Tag the full inventory so a consumer can filter it to what moved
		// without joining against the delta block by hand.
		delta.Tag(report.Components)

		if cfg.deltaOnly {
			report.Components = delta.DeltaComponents(report.Components)
			delta.Only = true
			report.Scan.AddWarning(
				"--delta-only: components lists only what changed, not the full inventory; " +
					"this file cannot be used as a --since baseline")
		}
		logf("delta vs %s: +%d added, -%d removed, ~%d changed",
			cfg.since, len(delta.Added), len(delta.Removed), len(delta.Changed))
	}

	logf("found %d components in %dms", len(report.Components), meta.DurationMS)

	// --- write ------------------------------------------------------------
	if cfg.toStdout {
		writer, _, err := output.WriterFor(formats[0])
		if err != nil {
			fmt.Fprintf(stderr, "swinv: %v\n", err)
			return exitUsage
		}
		if err := writer(stdout, report); err != nil {
			fmt.Fprintf(stderr, "swinv: writing %s: %v\n", formats[0], err)
			return exitFatal
		}
	} else if code := writeFiles(cfg, report, logf, stderr); code != exitOK {
		return code
	}

	if report.Scan.Incomplete {
		logf("inventory is INCOMPLETE (%d warnings)", len(report.Scan.Warnings))
		return exitIncomplete
	}
	return exitOK
}

// loadBaseline reads a previous swinv JSON report for --since.
//
// It accepts any schema version: the delta only needs the component list, and
// refusing to compare against an older report would make the flag useless
// exactly when it is most wanted — after an upgrade.
func loadBaseline(path string) (*model.Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline report: %w", err)
	}
	var r model.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parsing %s as an swinv JSON report: %w", path, err)
	}
	if r.SchemaVersion == "" {
		return nil, fmt.Errorf("%s does not look like an swinv report (no schema_version)", path)
	}
	// A --delta-only report contains only the components that changed. Diffing
	// against it would report every unchanged package on the machine as newly
	// added and everything else as removed, which is silently very wrong.
	if r.Delta != nil && r.Delta.Only {
		return nil, fmt.Errorf(
			"%s was written with --delta-only and holds only changed components, "+
				"so it cannot be used as a baseline; use a full inventory report instead", path)
	}
	return &r, nil
}

// writeFiles renders the report to every requested format under cfg.out.
func writeFiles(cfg *config, report *model.Report, logf func(string, ...any), stderr io.Writer) int {
	// Derived from --perm. The default (0755) keeps a collector running as
	// another user able to read the reports, which is the documented
	// deployment model; --perm 0600 tightens it to owner-only.
	// #nosec G301 -- the mode is operator-chosen and validated, see parsePerm
	if err := os.MkdirAll(cfg.out, cfg.dirPerm); err != nil {
		fmt.Fprintf(stderr, "swinv: creating %s: %v\n", cfg.out, err)
		return exitFatal
	}

	base := expandName(cfg.effectiveName(), report)
	formats, err := parseFormats(cfg.format, false)
	if err != nil {
		fmt.Fprintf(stderr, "swinv: %v\n", err)
		return exitUsage
	}

	for _, f := range formats {
		writer, ext, err := output.WriterFor(f)
		if err != nil {
			fmt.Fprintf(stderr, "swinv: %v\n", err)
			return exitUsage
		}
		target := filepath.Join(cfg.out, base+ext)
		if err := output.AtomicWriteFile(target, cfg.filePerm, func(w io.Writer) error {
			return writer(w, report)
		}); err != nil {
			fmt.Fprintf(stderr, "swinv: writing %s: %v\n", target, err)
			return exitFatal
		}
		logf("wrote %s", target)

		if cfg.latestSymlink {
			link := filepath.Join(cfg.out, latestBase(report)+ext)
			// In overwrite mode the target and the symlink would collide.
			if link == target {
				continue
			}
			if err := output.UpdateSymlink(link, filepath.Base(target)); err != nil {
				// A missing symlink is not worth failing a good inventory over.
				fmt.Fprintf(stderr, "swinv: warning: updating %s: %v\n", link, err)
			}
		}
	}
	return exitOK
}

// effectiveName returns the name template to use: an explicit --name if given,
// otherwise the template implied by --output-mode.
func (c *config) effectiveName() string {
	if c.nameSet && c.name != "" {
		return c.name
	}
	return defaultNameTemplates[c.outputMode]
}

// expandName substitutes the supported placeholders in a name template.
func expandName(tmpl string, r *model.Report) string {
	host := r.Host.Hostname
	if host == "" {
		host = "unknown-host"
	}
	repl := strings.NewReplacer(
		"{hostname}", sanitize(host),
		"{machine_id}", sanitize(r.Host.MachineID),
		"{date}", r.Scan.StartedAt.UTC().Format("20060102"),
		// Millisecond precision: with second precision two runs started in the
		// same second silently overwrite each other in --output-mode timestamped.
		"{datetime}", r.Scan.StartedAt.UTC().Format("20060102T150405.000Z"),
	)
	out := sanitize(repl.Replace(tmpl))
	if out == "" {
		out = "inventory"
	}
	return out
}

// latestBase is the basename of the "-latest" symlink family.
func latestBase(r *model.Report) string {
	host := r.Host.Hostname
	if host == "" {
		host = "unknown-host"
	}
	return sanitize(host) + "-latest"
}

// sanitize strips path separators and other characters that have no business
// in a filename, so a hostile hostname cannot escape the output directory.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.':
			return r
		default:
			return -1
		}
	}, s)
}

// parseFormats splits and validates the --format list.
func parseFormats(list string, forStdout bool) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if _, _, err := output.WriterFor(f); err != nil {
			return nil, fmt.Errorf("unknown --format %q (want json, csv, ndjson, or cyclonedx-json)", f)
		}
		if seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, errors.New("--format is empty")
	}
	if forStdout && len(out) != 1 {
		return nil, fmt.Errorf("--stdout requires exactly one --format, got %d", len(out))
	}
	return out, nil
}

// validModes returns the --output-mode names, sorted, for error messages.
func validModes() []string {
	out := make([]string, 0, len(defaultNameTemplates))
	for m := range defaultNameTemplates {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// buildExcludes computes the exclusion patterns for a filesystem scan and
// records them, along with any warnings, in the report metadata.
//
// Split out of run so the Windows path can skip it entirely: there is nothing
// to exclude from a registry read, and recording Linux layout exclusions in a
// Windows report would describe work that never happened.
func buildExcludes(cfg *config, meta *model.ScanMeta, stderr io.Writer) ([]string, error) {
	patterns, warnings, err := scan.BuildExcludes(scan.ExcludeOptions{
		Root:              cfg.root,
		UserExcludes:      cfg.excludes,
		AutoExcludeMounts: !cfg.noAutoExclude,
		NoSnap:            cfg.noSnap,
		NoFlatpak:         cfg.noFlatpak,
		IncludeHome:       cfg.includeHome,
	})
	if err != nil {
		fmt.Fprintf(stderr, "swinv: %v\n", err)
		return nil, err
	}
	meta.Excluded = patterns
	for _, w := range warnings {
		meta.AddWarning(w)
	}
	return patterns, nil
}
