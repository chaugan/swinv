package main

import (
	"context"
	"fmt"
	"sort"

	"github.com/chaugan/swinv/internal/elflink"
	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/service"
)

// ELF scope names.
const (
	elfScopeListening = "listening"
	elfScopeAll       = "all"
	elfScopeOff       = "off"
)

// validateELFScope rejects a typo as a usage error rather than a silent
// omission, for the same reason --ndjson-include does.
func validateELFScope(scope string) error {
	switch scope {
	case elfScopeListening, elfScopeAll, elfScopeOff:
		return nil
	}
	return fmt.Errorf("unknown --elf-scope %q (want listening, all, or off)", scope)
}

// linkProbe is what the pre-scan ELF pass produced: links per executable, and
// the library paths the scan's ownership probe should resolve.
type linkProbe struct {
	// byExe maps an executable (host path, or a container path prefixed by
	// its probe root) to its links.
	byExe map[string][]elflink.Link

	// libPaths is the union of resolved library paths, handed to the scan's
	// OwnerProbe so each library can be joined to its owning package.
	libPaths []string

	// walked is every executable probed under --elf-scope all, in order.
	walked []string

	truncated bool
}

// probeELF runs before the scan, because the scan's ownership probe needs the
// library paths in hand: a component's recorded locations are its evidence
// files, so the only way to name the package behind libcrypto.so.3 is to ask
// the package databases about that exact path while they are being read.
//
// Linux only. An ELF probe of a Windows host would find nothing, and the PE
// import table is a different feature.
func probeELF(ctx context.Context, cfg *config, listeners *service.Result, logf func(string, ...any)) *linkProbe {
	if cfg.elfScope == elfScopeOff || !service.Supported() || listeners == nil {
		return &linkProbe{byExe: map[string][]elflink.Link{}}
	}

	out := &linkProbe{byExe: map[string][]elflink.Link{}}
	libSet := map[string]bool{}

	// The listening executables, always: they are the ones the exposure
	// question is asked about, and there are a few dozen at most.
	for _, exe := range listeners.ExePaths() {
		links, err := elflink.Probe(exe, elflink.Options{Root: "/", Symbols: cfg.elfSymbols})
		if err != nil || len(links) == 0 {
			continue
		}
		out.byExe[exe] = links
		for _, l := range links {
			if l.Path != "" {
				libSet[l.Path] = true
			}
		}
	}

	// Everything, when asked. The walk is bounded and the cost is stated up
	// front rather than discovered: 5,845 ELF objects took about a minute and
	// a half on the development host, most of it walking /opt.
	if cfg.elfScope == elfScopeAll {
		paths, truncated := elflink.FindELF(ctx, cfg.root)
		out.truncated = truncated
		logf("elf: probing %d binaries under %s", len(paths), cfg.root)
		all, libs := elflink.ProbeAll(ctx, cfg.root, paths, cfg.elfSymbols)
		for exe, links := range all {
			if _, seen := out.byExe[exe]; !seen {
				out.byExe[exe] = links
				out.walked = append(out.walked, exe)
			} else {
				out.walked = append(out.walked, exe)
			}
		}
		sort.Strings(out.walked)
		for _, l := range libs {
			libSet[l] = true
		}
	}

	out.libPaths = make([]string, 0, len(libSet))
	for l := range libSet {
		out.libPaths = append(out.libPaths, l)
	}
	sort.Strings(out.libPaths)

	if n := len(out.byExe); n > 0 {
		logf("elf: %d binarie(s) probed, %d distinct librarie(s) to resolve", n, len(out.libPaths))
	}
	return out
}

// modelLinks converts probed links, filling each library's owning package from
// the scan's resolved file owners.
func modelLinks(links []elflink.Link, fileOwners map[string][]string) []model.Link {
	out := make([]model.Link, 0, len(links))
	for _, l := range links {
		ml := model.Link{
			Soname:           l.Soname,
			Path:             l.Path,
			Transitive:       !l.Direct,
			NSymbols:         l.NSymbols,
			Symbols:          l.Symbols,
			SymbolsTruncated: l.Truncated,
		}
		if owners := fileOwners[l.Path]; len(owners) > 0 {
			ml.PURL = owners[0]
		}
		out = append(out, ml)
	}
	return out
}

// attachLinks puts each probed executable's links where they belong: on the
// service that is listening with it, and -- under --elf-scope all -- into the
// report's own links table.
func attachLinks(cfg *config, report *model.Report, probe *linkProbe, fileOwners map[string][]string) {
	if len(probe.byExe) == 0 {
		return
	}

	for i := range report.Services {
		exe := report.Services[i].Executable
		links, ok := probe.byExe[exe]
		if !ok {
			continue
		}
		report.Services[i].Links = modelLinks(links, fileOwners)
		report.Services[i].Evidence = append(report.Services[i].Evidence, fmt.Sprintf(
			"links %d shared librarie(s) at link time; dlopen'd modules are not visible here",
			len(links)))
	}

	if cfg.elfScope == elfScopeAll {
		report.Links = make([]model.BinaryLinks, 0, len(probe.walked))
		for _, exe := range probe.walked {
			entry := model.BinaryLinks{
				Executable: exe,
				Links:      modelLinks(probe.byExe[exe], fileOwners),
			}
			if owners := fileOwners[exe]; len(owners) > 0 {
				entry.PURL = owners[0]
			}
			report.Links = append(report.Links, entry)
		}
		if probe.truncated {
			report.Scan.AddWarning(
				"the --elf-scope all walk hit its file cap; the links table is incomplete")
		}
	}
}

// ownerProbePaths is everything the scan's ownership probe should resolve:
// the listening executables, every library they and the walked binaries load,
// and the walked binaries themselves.
func ownerProbePaths(listeners *service.Result, probe *linkProbe) []string {
	out := listeners.ExePaths() // nil-safe: ExePaths has a pointer receiver guard
	out = append(out, probe.libPaths...)
	out = append(out, probe.walked...)
	return out
}

// linkSummary is the one line an operator reads about this section.
func linkSummary(report *model.Report) string {
	var withLinks, unowned int
	for _, s := range report.Services {
		if len(s.Links) == 0 {
			continue
		}
		withLinks++
		for _, l := range s.Links {
			if l.PURL == "" && l.Path != "" {
				unowned++
			}
		}
	}
	out := fmt.Sprintf("%d listening service(s) with resolved libraries", withLinks)
	if unowned > 0 {
		out += fmt.Sprintf(", %d librarie(s) no package owns", unowned)
	}
	if len(report.Links) > 0 {
		out += fmt.Sprintf("; %d binarie(s) in the full links table", len(report.Links))
	}
	return out
}
