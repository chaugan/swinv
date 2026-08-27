//go:build windows

package main

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/pelink"
	"github.com/chaugan/swinv/internal/scan"
	"github.com/chaugan/swinv/internal/service"
)

// attachPELinks is the Windows half of --elf-scope: PE import tables,
// resolved application-directory-first, joined to the products the inventory
// already identified. The flag keeps its ELF name so one timer unit works on
// both platforms; the help says what it means here.
//
// listening probes the executables behind open ports. all probes every
// executable file the MFT enumeration saw - which needs --full-scan, because
// the enumeration is the index and walking the filesystem a second time to
// rebuild it would be absurd.
//
// It runs after attribution because the join needs the finished component
// list, where the ELF probe runs before the scan because its join rides the
// package databases' file lists - two roads to the same record shape.
func attachPELinks(ctx context.Context, cfg *config, report *model.Report, result *scan.Result, logf func(string, ...any)) {
	if cfg.elfScope == elfScopeOff {
		return
	}

	seen := map[string]bool{}
	var paths []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	for i := range report.Services {
		if report.Services[i].Container == "" {
			add(report.Services[i].Executable)
		}
	}

	allScope := false
	if cfg.elfScope == elfScopeAll {
		if len(result.WinExecutables) > 0 {
			allScope = true
			for _, p := range result.WinExecutables {
				add(p)
			}
		} else {
			logf("elf-scope all needs --full-scan on Windows (the MFT enumeration is the " +
				"index of the machine's binaries); probing the listening executables only")
		}
	}
	if len(paths) == 0 {
		return
	}

	start := time.Now()
	byExe := pelink.ProbeAll(ctx, paths, pelink.Options{
		Symbols: cfg.elfSymbols,
		// The politeness contract is the scan's, not only the scheduler's:
		// every open is scanned by the antivirus at its own priority, so an
		// unpaced probe over 100k files makes the AV a foreground workload
		// no background-mode flag can soften. --fast means now, as always.
		Polite: !cfg.fast,
	}, cfg.parallelism)
	if len(byExe) == 0 {
		return
	}

	ix := service.NewOwnerIndex(report.Components)
	nlinks := 0
	for i := range report.Services {
		s := &report.Services[i]
		links, ok := byExe[s.Executable]
		if !ok || s.Container != "" {
			continue
		}
		s.Links = peModelLinks(links, ix)
		s.Evidence = append(s.Evidence, fmt.Sprintf(
			"links %d DLL(s) via the import table; LoadLibrary'd and delay-loaded "+
				"modules are not visible here", len(links)))
	}

	if allScope {
		// Every probed binary, sorted so two runs of an unchanged machine
		// produce identical output. linkLines dedups the listeners out of
		// this list when it streams.
		probed := make([]string, 0, len(byExe))
		for exe := range byExe {
			probed = append(probed, exe)
		}
		sort.Strings(probed)
		report.Links = make([]model.BinaryLinks, 0, len(probed))
		for _, exe := range probed {
			entry := model.BinaryLinks{
				Executable: exe,
				Links:      peModelLinks(byExe[exe], ix),
			}
			if ids, _ := ix.Owners(exe); len(ids) > 0 {
				entry.PURL = ids[0]
			}
			report.Links = append(report.Links, entry)
			nlinks += len(entry.Links)
		}
	} else {
		for _, links := range byExe {
			nlinks += len(links)
		}
	}
	logf("pe: %d of %d executable file(s) carry an import table, %d DLL link(s) in %s",
		len(byExe), len(paths), nlinks, time.Since(start).Round(time.Second))
}

func peModelLinks(links []pelink.Link, ix *service.OwnerIndex) []model.Link {
	out := make([]model.Link, 0, len(links))
	for _, l := range links {
		ml := model.Link{
			Soname:           l.Name,
			Path:             l.Path,
			Transitive:       !l.Direct,
			NSymbols:         l.NSymbols,
			Symbols:          l.Symbols,
			SymbolsTruncated: l.SymbolsTruncated,
		}
		if l.Path != "" {
			ids, osComponent := ix.Owners(l.Path)
			if len(ids) > 0 {
				ml.PURL = ids[0]
			}
			ml.OSComponent = osComponent
		}
		out = append(out, ml)
	}
	return out
}
