//go:build windows

package main

import (
	"context"
	"fmt"

	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/scan"
	"github.com/chaugan/swinv/internal/usn"
	"github.com/chaugan/swinv/internal/wincollect"
)

// platformScan runs the Windows collector instead of the Syft filesystem scan.
//
// Windows keeps its record of installed software in the registry, not on the
// filesystem, so walking the tree is the wrong shape here: measured on a real
// machine, Syft's resolver did not finish scanning C:\Program Files inside ten
// minutes, because it opens every file it sees to sniff a MIME type and every
// open is intercepted by antivirus. Reading the uninstall keys takes no time at
// all and answers the question directly.
func platformScan(ctx context.Context, cfg *config, logf func(string, ...any)) (*scan.Result, bool, error) {
	volumes, err := usn.ParseVolumes(cfg.volumes)
	if err != nil {
		return nil, true, err
	}

	res, err := wincollect.Collect(ctx, wincollect.Options{
		Volumes:     volumes,
		FullScan:    cfg.fullScan,
		Parallelism: cfg.parallelism,
		Logf:        logf,
	})
	if err != nil {
		return nil, true, err
	}

	catalogers := []string{"windows-registry-cataloger"}
	if cfg.fullScan {
		catalogers = append(catalogers, "windows-pe-cataloger")
	}

	out := &scan.Result{
		Components: model.Normalize(res.Components),
		Catalogers: catalogers,
		Warnings:   res.Warnings,
		Incomplete: res.Incomplete,
	}

	if !cfg.fullScan {
		// Said plainly, because the difference between "nothing else is
		// installed" and "nothing else was looked for" is the whole value of
		// an inventory.
		out.Warnings = append(out.Warnings,
			"only the uninstall registry was read; software that registers no uninstall "+
				"entry -- unpacked tools, per-user installs under another account, anything "+
				"copied onto the machine -- is not in this inventory. Pass --full-scan to "+
				"enumerate the filesystem as well")
	} else {
		logf("windows: %d registry products, %d executables enumerated, %d attributed, "+
			"%d opened, %d without version info",
			res.Stats.RegistryProducts, res.Stats.Enumerated, res.Stats.Attributed,
			res.Stats.Opened, res.Stats.NoVersionInfo)
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"%d of %d enumerated executables were attributed to a registry product and not "+
				"opened; %d were opened to extract a version",
			res.Stats.Attributed, res.Stats.Enumerated, res.Stats.Opened))
	}
	return out, true, nil
}
