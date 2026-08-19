// Package scan is swinv's Syft integration.
//
// It is the only package in swinv permitted to import github.com/anchore/syft.
// Everything downstream operates on internal/model types, which is what keeps
// a Syft API break contained to this file and leaves room for a second
// collection backend later without touching the writers.
package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"

	"github.com/chrzz/swinv/internal/model"

	// Syft v1.51.0's RPM cataloger opens the RPM package database through
	// database/sql and needs a registered "sqlite" driver. Without this blank
	// import CreateSBOM does not merely skip RPM databases, it fails outright
	// with "sqlite driver is required" — VERIFIED against v1.51.0, not
	// speculative. modernc.org/sqlite is a pure-Go driver, so registering it
	// here keeps CGO_ENABLED=0 builds working. Do not remove this import.
	_ "modernc.org/sqlite"
)

// toolName is the tool identity recorded in the Syft SBOM descriptor.
const toolName = "swinv"

// syftModulePath is the module whose version SyftVersion reports.
const syftModulePath = "github.com/anchore/syft"

// unknownVersion is what the version helpers report when build information is
// unavailable, which happens for binaries built without module information.
const unknownVersion = "unknown"

// Options controls a single scan. The zero value scans "/" with Syft's
// defaults and no exclusions, which is correct but slow; callers should build
// Excludes with BuildExcludes first.
type Options struct {
	// Root is the filesystem root to scan, normally "/".
	Root string

	// Excludes are final, already-validated exclusion patterns as produced by
	// BuildExcludes. Every pattern must satisfy ValidatePattern or source
	// construction fails.
	Excludes []string

	// CatalogerExpr is a Syft cataloger selection expression ("+foo,-bar").
	// Empty means the default installed+directory selection.
	CatalogerExpr string

	// FileOwnership enables package-to-file ownership relationships. It is the
	// expensive part of a full-root scan, but it is what lets Syft drop binary
	// packages already claimed by an OS package. Default true.
	FileOwnership bool

	// Parallelism is the cataloger worker count; 0 means runtime.NumCPU().
	Parallelism int

	// Verbose emits per-stage timing to stderr. Never to stdout: stdout is
	// reserved for --stdout report data.
	Verbose bool

	// Hash fills Component.SHA256 with the digest of each component's primary
	// on-disk file. Off by default: it reads every such file in full.
	Hash bool

	// SkipSymlinkPreflight disables the symlink quarantine pass. The preflight
	// costs one lstat-only walk but prevents a single unresolvable symlink from
	// aborting the entire scan; see QuarantineSymlinks. Leave it off.
	SkipSymlinkPreflight bool
}

// Distro is the Linux distribution Syft identified from the scanned tree. It
// is preferred over the values hostfacts reads from the running system,
// because it describes the tree that was actually scanned.
type Distro struct {
	ID         string
	VersionID  string
	PrettyName string
}

// Result is everything a scan produced. A Result is returned even when
// cataloging failed part-way: a partial inventory is far more useful than
// none, and Incomplete plus Warnings tell the caller what was lost.
type Result struct {
	// Components are the discovered packages, already passed through
	// model.Normalize, so they are deduplicated and deterministically sorted.
	Components []model.Component

	// Distro is what Syft determined about the scanned tree, or nil when it
	// could not determine anything.
	Distro *Distro

	// Catalogers is the selection actually applied, for ScanMeta.Catalogers.
	Catalogers []string

	// Warnings are human-readable notes about what degraded the scan.
	Warnings []string

	// Incomplete is true when a cataloger failed and the inventory may be
	// missing an ecosystem. The caller should exit 1.
	Incomplete bool

	// QuarantinedSymlinks are exclusion patterns the symlink preflight added
	// on top of the configured Excludes, so the caller can record the full
	// effective exclusion list in ScanMeta.Excluded.
	QuarantinedSymlinks []string

	// Unknowns is the number of files Syft saw but could not identify. Only
	// the count is surfaced; the list is large and low-value.
	Unknowns int
}

// Run scans opts.Root with Syft and converts the result into model
// components.
//
// A failing cataloger never aborts the run: it is recorded in Warnings, sets
// Incomplete, and Run still returns everything that was collected with a nil
// error. Only two things produce a non-nil error — the source could not be
// constructed, and the context was cancelled or its deadline expired. Context
// failures are wrapped so errors.Is(err, context.DeadlineExceeded) and
// errors.Is(err, context.Canceled) work on the returned error, which is what
// lets the caller distinguish exit code 4 from exit code 3.
func Run(ctx context.Context, opts Options) (*Result, error) {
	res := &Result{Components: []model.Component{}}

	root := normalizeRoot(opts.Root)
	absRoot, err := filepath.Abs(root)
	if err != nil {
		// filepath.Abs only fails when the working directory is unavailable;
		// the cleaned root is still the best answer we have.
		absRoot = root
	}
	absRoot = path.Clean(filepath.ToSlash(absRoot))

	if cerr := contextError(ctx, nil); cerr != nil {
		return nil, cerr
	}

	// Syft only validates exclusion patterns when the file resolver is built,
	// which is inside CreateSBOM, where a failure would be reported as a
	// cataloging problem rather than the configuration error it is. Check them
	// here so a bad pattern is fatal and names itself.
	for _, p := range opts.Excludes {
		if err := ValidatePattern(p); err != nil {
			return nil, fmt.Errorf("unable to construct scan source for %q: %w", absRoot, err)
		}
	}

	// --- stage 0: symlink preflight ---------------------------------------
	// A symlink whose target we cannot resolve makes Syft's indexer abort the
	// whole scan, and excluding the target does not help because the fatal
	// resolution happens before any exclusion visitor runs. Quarantine the
	// links themselves first. See QuarantineSymlinks for the full mechanism.
	var quarantined, preflightWarnings []string
	if !opts.SkipSymlinkPreflight {
		preflightStart := time.Now()
		quarantined, preflightWarnings = QuarantineSymlinks(ctx, absRoot, opts.Excludes)
		opts.logf("symlink preflight completed in %s (%d symlink(s) quarantined)",
			roundDuration(time.Since(preflightStart)), len(quarantined))
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	// --- stage 1: source construction ------------------------------------
	started := time.Now()
	// Syft rewrites the exclusion patterns IN PLACE, replacing the leading
	// "./" with the absolute scan root (see directorysource.getDirectoryExclusionFunctions:
	// `exclusions[idx] = root + exclusion`). Handing it our own slice would
	// therefore corrupt the caller's list — the same backing array is what
	// cmd/swinv records in ScanMeta.Excluded, so the report would show
	// "/abs/root/proc/**" instead of the "./proc/**" the operator configured,
	// and the recorded list would change with the scan root. Pass a copy.
	res.QuarantinedSymlinks = quarantined
	res.Warnings = append(res.Warnings, preflightWarnings...)

	excludes := append(append([]string(nil), opts.Excludes...), quarantined...)
	src, err := syft.GetSource(ctx, absRoot, syft.DefaultGetSourceConfig().
		// Force the directory provider. Without this Syft first tries to
		// interpret the root as a container image reference, which is wasted
		// work and produces confusing errors.
		WithSources("dir").
		WithExcludeConfig(source.ExcludeConfig{Paths: excludes}))
	if err != nil {
		if cerr := contextError(ctx, err); cerr != nil {
			return nil, cerr
		}
		return nil, fmt.Errorf("unable to construct scan source for %q: %w", absRoot, err)
	}
	defer func() { _ = src.Close() }()
	opts.logf("source constructed in %s (root %s, %d exclusion patterns)",
		roundDuration(time.Since(started)), absRoot, len(excludes))

	// --- stage 2: cataloging ----------------------------------------------
	selection, applied := catalogerSelection(opts.CatalogerExpr)
	res.Catalogers = applied

	started = time.Now()
	s, err := syft.CreateSBOM(ctx, src, createSBOMConfig(opts, selection))
	if err != nil {
		if cerr := contextError(ctx, err); cerr != nil {
			return nil, cerr
		}
		// A cataloger failure is recorded and the run continues. Syft returns
		// no SBOM in this case, so what survives is whatever the conversion
		// below finds — possibly nothing — but the report is still written.
		res.Incomplete = true
		res.addWarning(fmt.Sprintf("cataloging did not complete, the inventory may be missing packages: %v", err))
		opts.logf("cataloging failed after %s: %v", roundDuration(time.Since(started)), err)
	} else {
		opts.logf("cataloging completed in %s", roundDuration(time.Since(started)))
	}

	// --- stage 3: conversion ----------------------------------------------
	started = time.Now()
	if s != nil {
		res.Distro = distroFrom(s)

		if n := len(s.Artifacts.Unknowns); n > 0 {
			res.Unknowns = n
			// The count only. The list runs to thousands of paths on a normal
			// host and tells the operator nothing actionable.
			res.addWarning(fmt.Sprintf("%d files could not be identified", n))
		}

		var components []model.Component
		if s.Artifacts.Packages != nil {
			// Enumerate feeds from a goroutine; drain it completely so that
			// goroutine always finishes, even on an otherwise uninteresting
			// package.
			for p := range s.Artifacts.Packages.Enumerate() {
				components = append(components, componentFromPackage(p, absRoot))
			}
		}
		res.Components = model.Normalize(components)
	}
	if opts.Hash {
		hashStart := time.Now()
		hashed, hashWarnings := HashComponents(ctx, absRoot, opts.Parallelism, res.Components)
		res.Warnings = append(res.Warnings, hashWarnings...)
		opts.logf("hashed %d of %d component files in %s",
			hashed, len(res.Components), roundDuration(time.Since(hashStart)))
	}

	opts.logf("conversion completed in %s (%d components)",
		roundDuration(time.Since(started)), len(res.Components))

	if cerr := contextError(ctx, nil); cerr != nil {
		return nil, cerr
	}
	return res, nil
}

// SyftVersion reports the version of github.com/anchore/syft this binary was
// built against, or "unknown" when build information is unavailable.
func SyftVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return unknownVersion
	}
	for _, dep := range info.Deps {
		if dep == nil || dep.Path != syftModulePath {
			continue
		}
		// A replace directive is what actually ends up in the binary.
		if dep.Replace != nil && dep.Replace.Version != "" {
			return dep.Replace.Version
		}
		if dep.Version != "" {
			return dep.Version
		}
		return unknownVersion
	}
	return unknownVersion
}

// createSBOMConfig builds the Syft cataloging configuration for a run.
func createSBOMConfig(opts Options, selection cataloging.SelectionRequest) *syft.CreateSBOMConfig {
	// ExcludeBinaryPackagesWithFileOwnershipOverlap stays at its default of
	// true: it is what stops the binary classifier from reporting
	// /usr/bin/python3.11 as its own component when the python3.11 deb already
	// claims that file. PackageFileOwnership is the expensive half and is the
	// one the operator can turn off.
	relationships := cataloging.DefaultRelationshipsConfig().
		WithPackageFileOwnership(opts.FileOwnership)

	return syft.DefaultCreateSBOMConfig().
		WithTool(toolName, toolVersion()).
		// swinv inventories software, not files; file digests and metadata
		// would multiply both runtime and output size for no benefit.
		WithoutFiles().
		WithParallelism(opts.Parallelism).
		// SquashedScope is the only scope that makes sense for a live
		// filesystem; the others are container-image concepts.
		WithSearchConfig(cataloging.DefaultSearchConfig().WithScope(source.SquashedScope)).
		WithRelationshipsConfig(relationships).
		WithCatalogerSelection(selection)
}

// catalogerSelection turns the operator's --catalogers expression into a Syft
// selection request, and returns the selection terms actually applied so they
// can be recorded in ScanMeta.Catalogers.
//
// An empty expression selects the installed and directory tags. That baseline
// already covers loose binaries: the binary classifier, ELF, PE, JVM, and
// kernel catalogers all carry the directory tag. It deliberately leaves the
// sbom cataloger off, because an SBOM file found on disk is not evidence that
// the software it describes is installed here.
func catalogerSelection(expr string) (cataloging.SelectionRequest, []string) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		applied := []string{pkgcataloging.InstalledTag, pkgcataloging.DirectoryTag}
		return cataloging.NewSelectionRequest().WithDefaults(applied...), applied
	}

	var terms []string
	for _, term := range strings.Split(expr, ",") {
		if term = strings.TrimSpace(term); term != "" {
			terms = append(terms, term)
		}
	}
	if len(terms) == 0 {
		applied := []string{pkgcataloging.InstalledTag, pkgcataloging.DirectoryTag}
		return cataloging.NewSelectionRequest().WithDefaults(applied...), applied
	}
	return cataloging.NewSelectionRequest().WithExpression(terms...), terms
}

// distroFrom extracts the Linux release Syft identified. Artifacts.
// LinuxDistribution may be nil — on a tree with no os-release, or when
// cataloging failed early — and a nil Distro is the correct answer then, so
// the caller can fall back to hostfacts.
func distroFrom(s *sbom.SBOM) *Distro {
	if s == nil || s.Artifacts.LinuxDistribution == nil {
		return nil
	}
	d := s.Artifacts.LinuxDistribution
	return &Distro{
		ID:         d.ID,
		VersionID:  d.VersionID,
		PrettyName: d.PrettyName,
	}
}

// componentFromPackage converts one Syft package into a model component.
// absRoot is the scan root, used to turn Syft's root-relative paths back into
// absolute system paths.
func componentFromPackage(p pkg.Package, absRoot string) model.Component {
	c := model.Component{
		Name:     p.Name,
		Version:  p.Version,
		Type:     string(p.Type),
		Language: string(p.Language),
		PURL:     p.PURL,
		FoundBy:  p.FoundBy,
	}

	for _, cp := range p.CPEs {
		if s := cp.Attributes.String(); s != "" {
			c.CPEs = append(c.CPEs, s)
		}
	}

	for _, l := range p.Licenses.ToSlice() {
		// Prefer the parsed SPDX expression; fall back to the raw value so a
		// non-SPDX licence string is still reported rather than dropped.
		value := strings.TrimSpace(l.SPDXExpression)
		if value == "" {
			value = strings.TrimSpace(l.Value)
		}
		if value != "" {
			c.Licenses = append(c.Licenses, value)
		}
	}

	for _, loc := range p.Locations.ToSlice() {
		// RealPath is the path after symlink resolution and is what we want to
		// record; AccessPath is how the file was reached and is the only thing
		// available for some catalogers.
		raw := loc.RealPath
		if strings.TrimSpace(raw) == "" {
			raw = loc.AccessPath
		}
		if p := normalizeLocation(raw, absRoot); p != "" {
			c.Locations = append(c.Locations, p)
		}
	}

	// model.Normalize sorts and deduplicates these slices for the whole set;
	// leaving them in discovery order here keeps the conversion single-pass.
	return c
}

// normalizeLocation renders a Syft location as an absolute path on the scanned
// system. Syft's directory resolver reports paths relative to the scan root
// ("var/lib/dpkg/status"), so the leading slash is restored; when a cataloger
// reports a fully qualified path instead, the scan root prefix is stripped, so
// that scanning a fixture tree or a mounted image records the path the file
// has on that system rather than where it happened to be mounted. A root of
// "/" makes the strip a no-op.
func normalizeLocation(p, absRoot string) string {
	p = strings.TrimSpace(filepath.ToSlash(p))
	if p == "" {
		return ""
	}

	if strings.HasPrefix(p, "/") {
		if absRoot != "" && absRoot != "/" {
			switch {
			case p == absRoot:
				p = "/"
			case strings.HasPrefix(p, absRoot+"/"):
				p = p[len(absRoot):]
			}
		}
	} else {
		p = "/" + p
	}

	return path.Clean(p)
}

// contextError reports a cancellation or deadline failure as an error that
// wraps the context sentinel, so the caller can tell a timeout (exit 4) from a
// fatal source error (exit 3). It returns nil when neither the context nor the
// supplied error indicates cancellation.
func contextError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return fmt.Errorf("scan aborted: %w", err)
	case ctx.Err() != nil && err != nil:
		return fmt.Errorf("scan aborted: %w (underlying failure: %w)", ctx.Err(), err)
	case ctx.Err() != nil:
		return fmt.Errorf("scan aborted: %w", ctx.Err())
	}
	return nil
}

// addWarning appends a warning, ignoring blanks and exact duplicates so a
// repeated cataloger failure does not fill the report.
func (r *Result) addWarning(w string) {
	w = strings.TrimSpace(w)
	if w == "" {
		return
	}
	for _, existing := range r.Warnings {
		if existing == w {
			return
		}
	}
	r.Warnings = append(r.Warnings, w)
}

// logf writes a per-stage status line to stderr when --verbose is set. All
// human-readable output goes to stderr; stdout belongs to the report.
func (o Options) logf(format string, args ...any) {
	if !o.Verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "swinv: "+format+"\n", args...)
}

// roundDuration trims timing output to something a human reads at a glance.
func roundDuration(d time.Duration) time.Duration {
	if d >= time.Second {
		return d.Round(time.Millisecond)
	}
	return d.Round(time.Microsecond)
}

// toolVersion reports swinv's own version for the Syft SBOM descriptor. The
// descriptor is never serialized by swinv, so build information is enough and
// no version needs to be threaded through Options.
func toolVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil || info.Main.Version == "" {
		return unknownVersion
	}
	return info.Main.Version
}
