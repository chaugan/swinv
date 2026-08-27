// Command swinv scans the local machine, enumerates installed software, and
// writes the inventory to local JSON and CSV files.
//
// By default it transmits nothing: files land on disk and collecting them
// afterwards is somebody else's job. --transmit adds an upload to one HTTPS
// endpoint without taking the files away, because the sites most likely to
// want this product are the ones that move files by means they already trust.
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

	"github.com/chaugan/swinv/internal/configsurface"
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

	// exitSourceFailed is the refusal to be quietly useless.
	//
	// A source that exists and could not be read produces a small, valid,
	// perfectly healthy-looking inventory. Fifteen components from a host with
	// four thousand is indistinguishable from a minimal machine, and every
	// layer downstream will agree it is fine. Exiting 0 there is the bug; this
	// code is the fix.
	exitSourceFailed = 5

	// exitTransmit is an upload that did not complete, or that completed and
	// did not reconcile. The inventory files are still written: a failure to
	// reach the server must never destroy the copy on disk.
	exitTransmit = 6
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
	heartbeat        bool
	ndjsonInclude    string
	elfScope         string
	elfSymbols       bool
	configScope      string
	forceFull        bool
	fullInterval     time.Duration
	catalogers       string
	noFileOwnership  bool
	noServices       bool
	noServiceCommand bool
	noContainers     bool
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

	transmit                  string
	transmitTokenFile         string
	transmitCert              string
	transmitKey               string
	transmitKeyPassphraseFile string
	transmitCA                string
	transmitPins              stringList
	transmitTLSMin            string
	transmitInsecure          bool
	transmitBatchLines        int
	transmitBatchBytes        string
	transmitBatchBytesN       int64
	transmitAttempts          int
	transmitTimeout           time.Duration
	transmitCheck             bool
	transmitOnly              bool
	transmitFrom              string
	transmitRateLimit         string
	transmitRateLimitN        int64
	transmitCompress          string
	transmitRequireComplete   bool

	// transmitInsecureWarned makes the certificate-verification opt-out
	// announce itself on every run rather than only in the help.
	transmitInsecureWarned bool

	nameSet         bool // whether --name was given explicitly
	fullIntervalSet bool // whether --full-interval was given explicitly
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

	if cfg.transmitInsecureWarned {
		// Not behind --quiet. --quiet is a promise about status output, not a
		// licence to hide that this run is shipping an inventory of the
		// machine to an unverified peer.
		fmt.Fprintln(stderr, "swinv: WARNING: --transmit-insecure: the server's certificate is not "+
			"being verified, so this upload can be intercepted and read")
	}

	// The run modes that talk to the server without scanning exit here,
	// before any collection machinery spins up.
	if cfg.transmitCheck {
		return runTransmitCheck(cfg, logf, stdout, stderr)
	}
	if cfg.transmitOnly || cfg.transmitFrom != "" {
		return runTransmitSend(cfg, logf, stderr)
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

	// --- what is listening, part one --------------------------------------
	// Taken before the scan so the scan can be told which executables to
	// resolve ownership for; see listenSnapshot.
	listeners, servicesSource := listenSnapshot(ctx, cfg, &meta, logf)

	// --- what those executables link --------------------------------------
	// Also before the scan, for the same reason one level down: naming the
	// package behind libcrypto.so.3 means asking the package databases about
	// that exact path while they are being read.
	elfProbe := probeELF(ctx, cfg, listeners, logf)

	configRoot := cfg.root
	if configRoot == "" {
		configRoot = "/"
	}
	configEntries := configsurface.Collect(ctx, configsurface.Options{
		Root:            configRoot,
		Scope:           cfg.configScope,
		IncludeCommands: !cfg.noServiceCommand,
	})
	if len(configEntries) > 0 {
		logf("config surface: %d entr(ies) collected", len(configEntries))
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
			OwnerProbe:       append(ownerProbePaths(listeners, elfProbe), configsurface.ExecutablePaths(configEntries)...),
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
		NDJSONInclude: parseNDJSONInclude(cfg.ndjsonInclude),
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

	// --- what is listening, part two --------------------------------------
	// After the components, because the attribution joins against them, and
	// before the delta, so that a --delta-only report still carries the
	// services block: "what changed" is most interesting about the things
	// serving traffic.
	attributeServices(ctx, cfg, report, listeners, result.FileOwners, logf)

	// Libraries onto services, and -- with --elf-scope all -- the full table.
	attachLinks(cfg, report, elfProbe, result.FileOwners)
	configsurface.AttachOwners(configEntries, result.FileOwners)
	report.ConfigSurface = configEntries
	if len(elfProbe.byExe) > 0 {
		logf("elf: %s", linkSummary(report))
	}

	// --- manifest ---------------------------------------------------------
	// Here, and not later, for two reasons. The component list is complete --
	// the packages found inside containers have just joined it -- and it has
	// not yet been trimmed by --delta-only, so the per-source counts describe
	// the machine rather than the subset this run happens to be reporting.
	failedSources := buildManifest(cfg, report, servicesSource)
	if len(failedSources) > 0 {
		report.Scan.Incomplete = true
		for _, name := range failedSources {
			report.Scan.AddWarning(fmt.Sprintf("source %s failed: %s",
				name, report.Scan.Sources[name].Reason))
		}
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

	// --- heartbeat --------------------------------------------------------
	// After the delta, because both describe change and the delta is the one
	// that alters the component list. Before writing, because it decides what
	// the NDJSON stream carries.
	applyHeartbeat(cfg, report, logf)

	// Warnings are what turn "378 components" from a fact into a qualified
	// one: whether something was not installed, or merely not looked for.
	// They were recorded in the report and never shown, so an operator whose
	// --full-scan silently did nothing -- because enumerating the MFT needs
	// elevation -- saw a clean run and a component count.
	for _, w := range report.Scan.Warnings {
		logf("warning: %s", w)
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

	// --- transmit ---------------------------------------------------------
	// After the files, deliberately. The copy on disk is the one an operator
	// can still act on when the server is unreachable, so it is written first
	// and is never conditional on the upload.
	transmitCode := exitOK
	switch {
	case cfg.transmit == "":
	case cfg.transmitRequireComplete && len(failedSources) > 0:
		// A partial inventory on the server reads as a healthy small host:
		// the matcher correctly reports few findings because few packages
		// were assessed, and every layer succeeds while the host goes
		// silently unassessed. Failing here, at the host, is where the
		// operator can still see the exit code.
		fmt.Fprintf(stderr, "swinv: not transmitting: %d inventory source(s) failed and the scan is "+
			"incomplete; the files are on disk, and --transmit-require-complete=false sends anyway\n",
			len(failedSources))
	default:
		sendCtx, cancelSend := context.WithTimeout(context.Background(), transmitDeadline(cfg))
		transmitCode = transmitReport(sendCtx, cfg, report, logf, stderr)
		cancelSend()
	}

	// A source that failed outranks everything else here. A partial inventory
	// that exits 0 is the failure this whole manifest exists to prevent, and
	// an operator whose timer only checks the exit code has to see it.
	if len(failedSources) > 0 {
		fmt.Fprintf(stderr,
			"swinv: %d of this host's inventory sources could not be read (%s); "+
				"the inventory is INCOMPLETE and its component count is wrong by an unknown amount\n",
			len(failedSources), strings.Join(failedSources, ", "))
		for _, name := range failedSources {
			fmt.Fprintf(stderr, "swinv:   %s: %s\n", name, report.Scan.Sources[name].Reason)
		}
		return exitSourceFailed
	}
	if transmitCode != exitOK {
		return transmitCode
	}
	if report.Scan.Incomplete {
		logf("this inventory is INCOMPLETE -- see the warnings above")
		return exitIncomplete
	}
	return exitOK
}

// loadBaseline reads a previous swinv JSON report for --since.
//
// It accepts any schema version: the delta only needs the component list, and
// refusing to compare against an older report would make the flag useless
// exactly when it is most wanted - after an upgrade.
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

		// The services sidecar rides along with the component CSV: same run,
		// same basename, same permissions.
		if f == "csv" {
			if code := writeServicesCSV(cfg, report, base, logf, stderr); code != exitOK {
				return code
			}
			if code := writeExposureCSV(cfg, report, base, logf, stderr); code != exitOK {
				return code
			}
		}

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
