//go:build windows

package main

import (
	"fmt"

	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/pelink"
	"github.com/chaugan/swinv/internal/service"
)

// attachPELinks is the Windows half of --elf-scope: every listening
// executable's PE import table, resolved application-directory-first, joined
// to the products the inventory already identified. The flag keeps its ELF
// name so one timer unit works on both platforms; the help says what it
// means here.
//
// It runs after attribution because the join needs the finished component
// list, where the ELF probe runs before the scan because its join rides the
// package databases' file lists - two roads to the same record shape.
func attachPELinks(cfg *config, report *model.Report, logf func(string, ...any)) {
	if cfg.elfScope == elfScopeOff {
		return
	}
	if cfg.elfScope == elfScopeAll {
		logf("elf-scope all: the PE walk is not built; probing the listening executables")
	}

	ix := service.NewOwnerIndex(report.Components)
	cache := map[string][]model.Link{}
	probed, nlinks := 0, 0
	for i := range report.Services {
		s := &report.Services[i]
		if s.Executable == "" || s.Container != "" {
			continue
		}
		links, ok := cache[s.Executable]
		if !ok {
			raw, err := pelink.Probe(s.Executable, pelink.Options{Symbols: cfg.elfSymbols})
			if err != nil || len(raw) == 0 {
				cache[s.Executable] = nil
				continue
			}
			links = peModelLinks(raw, ix)
			cache[s.Executable] = links
			probed++
			nlinks += len(links)
		}
		if len(links) == 0 {
			continue
		}
		s.Links = links
		s.Evidence = append(s.Evidence, fmt.Sprintf(
			"links %d DLL(s) via the import table; LoadLibrary'd and delay-loaded "+
				"modules are not visible here", len(links)))
	}
	if probed > 0 {
		logf("pe: %d binarie(s) probed, %d DLL link(s)", probed, nlinks)
	}
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
