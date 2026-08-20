package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/chaugan/swinv/internal/arp"
	"github.com/chaugan/swinv/internal/usn"
)

// executableExtensions are the files worth extracting a version from on
// Windows. Everything else on a volume -- resources, icons, localisation,
// documentation, data -- is discovered by the enumeration and then never
// opened, which is where the saving comes from.
var executableExtensions = map[string]bool{
	".exe": true, ".dll": true, ".sys": true,
	".ocx": true, ".cpl": true, ".drv": true,
}

func isExecutableName(name string) bool {
	return executableExtensions[strings.ToLower(filepath.Ext(name))]
}

// runUSNProbe enumerates the Master File Table of each requested volume and
// reports what it found, without scanning anything.
//
// This is a measuring instrument, not a scan. The Windows collector described
// in docs/WINDOWS.md does not exist yet; this exercises the one piece of it
// that does, so the numbers that decide the rest of the design -- how many
// files a volume holds, how many are candidates, how long enumeration takes --
// come from real machines instead of from a hosted runner with nothing
// installed on it.
func runUSNProbe(ctx context.Context, volumes []string, out io.Writer, logf func(string, ...any)) int {
	if len(volumes) == 0 {
		volumes = []string{"C:"}
	}

	var grandRecords, grandKept int
	for _, volume := range volumes {
		start := time.Now()
		res, err := usn.Enumerate(ctx, usn.Options{
			Volume: volume,
			Keep:   func(name string, isDir bool, _ uint32) bool { return !isDir && isExecutableName(name) },
		})
		elapsed := time.Since(start)

		switch {
		case errors.Is(err, usn.ErrUnsupportedPlatform):
			fmt.Fprintln(out, "swinv: --usn-probe reads the NTFS Master File Table and only works on Windows")
			return exitUsage
		case errors.Is(err, usn.ErrNotElevated):
			fmt.Fprintf(out, "swinv: %s needs an elevated process; run this from an Administrator prompt\n", volume)
			return exitUsage
		case errors.Is(err, usn.ErrNotNTFS):
			fmt.Fprintf(out, "swinv: %v\n", err)
			return exitUsage
		case err != nil:
			fmt.Fprintf(out, "swinv: %v\n", err)
			return exitFatal
		}

		grandRecords += res.Records
		grandKept += len(res.Entries)

		logf("%s: %d MFT records in %s", volume, res.Records, elapsed.Round(time.Millisecond))
		logf("%s: %d directories, %d executables kept, %d paths unresolved",
			volume, res.Directories, len(res.Entries), res.Unresolved)
		if res.Records > 0 {
			logf("%s: kept %.1f%% -- the other %.1f%% were never opened",
				volume,
				100*float64(len(res.Entries))/float64(res.Records),
				100*(1-float64(len(res.Entries))/float64(res.Records)))
		}

		printTopDirectories(res.Entries, volume, logf)
		reportRegistryCoverage(res.Entries, volume, logf)
	}

	if len(volumes) > 1 && grandRecords > 0 {
		logf("total: %d records, %d executables (%.1f%%)",
			grandRecords, grandKept, 100*float64(grandKept)/float64(grandRecords))
	}
	return exitOK
}

// printTopDirectories shows where the candidates live, which is the quickest
// way to see whether an allowlist derived from the registry would cover them.
func printTopDirectories(entries []usn.Entry, volume string, logf func(string, ...any)) {
	const depth = 2

	counts := make(map[string]int)
	for _, e := range entries {
		if e.Path == "" {
			continue
		}
		counts[trimToDepth(e.Path, volume, depth)]++
	}

	type row struct {
		path string
		n    int
	}
	rows := make([]row, 0, len(counts))
	for p, n := range counts {
		rows = append(rows, row{p, n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].n != rows[j].n {
			return rows[i].n > rows[j].n
		}
		return rows[i].path < rows[j].path
	})

	limit := 12
	if len(rows) < limit {
		limit = len(rows)
	}
	for _, r := range rows[:limit] {
		logf("    %8d  %s", r.n, r.path)
	}
	if len(rows) > limit {
		logf("    ... and %d more directories", len(rows)-limit)
	}
}

// trimToDepth reduces a path to its first n components below the volume, so
// that C:\Program Files\Adobe\Reader\x.dll groups under C:\Program Files\Adobe.
//
// Paths under \Users are given three extra levels. Two components collapses
// every per-user install into "C:\Users\<name>", which hides the thing worth
// seeing: per-user software lives at AppData\Local\Programs and similar, it is
// real installed software -- editors, runtimes, Electron applications -- and it
// is exactly the category the registry covers least well, since it is
// registered in HKCU and another user's hive is not loaded.
func trimToDepth(path, volume string, n int) string {
	rest := strings.TrimPrefix(path, volume)
	rest = strings.TrimPrefix(rest, `\`)

	parts := strings.Split(rest, `\`)
	if len(parts) > 0 && strings.EqualFold(parts[0], "Users") {
		n += 3
	}

	// The last component is the file name and must never appear in a grouping:
	// a file sitting directly in the volume root would otherwise become its
	// own "directory" and clutter the summary with one-entry rows.
	if len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > n {
		parts = parts[:n]
	}
	if len(parts) == 0 {
		return volume + `\`
	}
	return volume + `\` + strings.Join(parts, `\`)
}

// reportRegistryCoverage answers the question the whole Windows design turns
// on: how much of what is on disk does the registry already account for?
//
// If the uninstall keys' InstallLocation values cover most candidates, an
// allowlist derived from them is the default scan and full enumeration is a
// fallback. If they do not, enumeration is load-bearing and --full-scan is the
// only way to see that software at all.
func reportRegistryCoverage(entries []usn.Entry, volume string, logf func(string, ...any)) {
	installed, err := arp.Read()
	if err != nil {
		logf("%s: could not read the uninstall registry (%v)", volume, err)
		return
	}

	var (
		fromInstallLocation []string
		fromAllSources      []string
		withLocation        int
		withAnySource       int
	)
	for _, e := range installed {
		if e.InstallLocation != "" {
			withLocation++
			fromInstallLocation = append(fromInstallLocation, strings.TrimRight(e.InstallLocation, `\`))
		}
		if locs := installLocations(e.InstallLocation, e.DisplayIcon, e.UninstallString); len(locs) > 0 {
			withAnySource++
			fromAllSources = append(fromAllSources, locs...)
		}
	}

	logf("%s: registry lists %d products; %d have InstallLocation, %d yield a directory from any field",
		volume, len(installed), withLocation, withAnySource)

	var all, thirdParty []string
	for _, e := range entries {
		if e.Path == "" || !strings.HasPrefix(strings.ToUpper(e.Path), strings.ToUpper(volume)) {
			continue
		}
		all = append(all, e.Path)
		if !osOrStoreTerritory(e.Path, volume) {
			thirdParty = append(thirdParty, e.Path)
		}
	}
	if len(all) == 0 {
		return
	}

	report := func(label string, paths, locations []string) {
		if len(paths) == 0 {
			return
		}
		covered, _ := coverageOf(paths, locations)
		logf("%s:   %-34s %6d of %6d  (%4.1f%%)", volume, label, covered, len(paths),
			100*float64(covered)/float64(len(paths)))
	}

	logf("%s: coverage by a registry-derived allowlist:", volume)
	report("InstallLocation, all files", all, fromInstallLocation)
	report("+DisplayIcon/UninstallString", all, fromAllSources)
	logf("%s: excluding OS and Store territory (%d of %d files):",
		volume, len(thirdParty), len(all))
	report("InstallLocation, third-party", thirdParty, fromInstallLocation)
	report("+DisplayIcon/UninstallString", thirdParty, fromAllSources)
}
