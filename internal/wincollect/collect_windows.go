//go:build windows

package wincollect

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chaugan/swinv/internal/appx"
	"github.com/chaugan/swinv/internal/arp"
	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/peversion"
	"github.com/chaugan/swinv/internal/usn"
)

// Cataloger names, which appear in each component's found_by and are how a
// consumer tells where a fact came from.
const (
	registryCataloger = "windows-registry-cataloger"
	appxCataloger     = "windows-appx-cataloger"
	updateCataloger   = "windows-update-cataloger"
	peCataloger       = "windows-pe-cataloger"
)

// Component types. Registry entries get "windows"; extracted executables reuse
// "binary", which already means the same thing on Linux.
const (
	typeWindows = "windows"
	typeMSIX    = "msix"
	typeHotfix  = "hotfix"
	typeBinary  = "binary"
)

// executableExtensions is what is worth opening. Everything else on a volume
// is discovered by enumeration and then left alone.
var executableExtensions = map[string]bool{
	".exe": true, ".dll": true, ".sys": true,
	".ocx": true, ".cpl": true, ".drv": true,
}

func isExecutable(name string) bool {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return executableExtensions[strings.ToLower(name[i:])]
	}
	return false
}

func collect(ctx context.Context, opts Options) (*Result, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	res := &Result{Components: []model.Component{}}

	// --- 1. the registry -------------------------------------------------
	// Products with name, version and publisher, no file opened. This is the
	// inventory; everything after it is about finding what it missed.
	installed, err := arp.Read()
	if err != nil {
		return nil, fmt.Errorf("wincollect: reading the uninstall registry: %w", err)
	}
	res.Stats.RegistryProducts = len(installed)

	locations := make([]string, 0, len(installed))
	for _, e := range installed {
		res.Components = append(res.Components, componentFromRegistry(e))
		locations = append(locations, InstallLocations(e.InstallLocation, e.DisplayIcon, e.UninstallString)...)
	}
	known := NewLocationSet(locations)
	logf("registry: %d installed products, %d distinct install locations",
		len(installed), known.Len())

	// --- 1b. Store apps and Windows updates ---------------------------------
	// Both are registry reads that open no files, so they belong with the
	// uninstall keys rather than behind --full-scan.
	collectPackages(res, logf)
	collectUpdates(res, logf)

	if !opts.FullScan {
		return res, nil
	}

	// --- 2. enumerate -----------------------------------------------------
	volumes := opts.Volumes
	if len(volumes) == 0 {
		volumes = []string{"C:"}
	}

	var toOpen []string
	for _, volume := range volumes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		start := time.Now()
		enumerated, err := usn.Enumerate(ctx, usn.Options{
			Volume: volume,
			Keep:   func(name string, isDir bool, _ uint32) bool { return !isDir && isExecutable(name) },
		})
		switch {
		case errors.Is(err, usn.ErrNotNTFS), errors.Is(err, usn.ErrNotElevated):
			// Neither is fatal: the registry inventory above still stands, and
			// reporting it is more useful than refusing to. But the operator
			// asked for a full scan and did not get one, so this is an
			// incomplete inventory rather than a successful small one --
			// otherwise a scheduled task that lost its elevation reports
			// success forever while quietly seeing a fraction of the machine.
			res.Incomplete = true
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"--full-scan could not enumerate %s (%v), so only the uninstall "+
					"registry was read; software that registers no uninstall entry is "+
					"missing from this inventory", volume, err))
			continue
		case err != nil:
			return nil, err
		}

		logf("%s: %d executables from %d MFT records in %s",
			volume, len(enumerated.Entries), enumerated.Records, time.Since(start).Round(time.Millisecond))
		res.Stats.Enumerated += len(enumerated.Entries)

		// --- 3. attribute -------------------------------------------------
		// A file under a known product's directory already has its version,
		// from the registry, for free. Opening it would be wasted work.
		var osOrStore int
		for _, e := range enumerated.Entries {
			if e.Path == "" {
				continue
			}
			if OSOrStoreTerritory(e.Path, volume) {
				osOrStore++
				continue
			}
			if known.Covers(e.Path) {
				res.Stats.Attributed++
				continue
			}
			toOpen = append(toOpen, e.Path)
		}
		res.Stats.OSOrStore += osOrStore

		if osOrStore > 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"%d executables under %s\\Windows and WindowsApps were not opened: operating "+
					"system components are represented by the installed updates above rather "+
					"than file by file, and Store apps come from the package registry",
				osOrStore, volume))
		}
	}

	// --- 4. extract -------------------------------------------------------
	if len(toOpen) == 0 {
		return res, nil
	}
	logf("extracting from %d files (%d attributed to a known product, %d skipped as OS or Store)",
		len(toOpen), res.Stats.Attributed, res.Stats.OSOrStore)

	extracted, opened, noInfo := extractAll(ctx, toOpen, opts.Parallelism, logf)
	res.Components = append(res.Components, extracted...)
	res.Stats.Opened = opened
	res.Stats.NoVersionInfo = noInfo

	return res, nil
}

// extractAll opens each candidate and reads its version resource.
//
// This is the only part of a Windows scan that opens a file, and on a machine
// with real-time antivirus every open is intercepted, so it dominates the
// runtime of everything above it put together.
func extractAll(ctx context.Context, paths []string, parallelism int, logf func(string, ...any)) (
	components []model.Component, opened, noInfo int) {

	if parallelism <= 0 {
		// A quarter of the CPUs, matching the politeness default elsewhere:
		// worker count sets the depth of the I/O queue this process presents,
		// which is most of what decides whether the machine feels slow.
		if parallelism = runtime.NumCPU() / 4; parallelism < 1 {
			parallelism = 1
		}
	}

	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		queue = make(chan string)
		start = time.Now()
		done  int
	)

	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range queue {
				info, err := peversion.Read(path)

				mu.Lock()
				opened++
				if errors.Is(err, peversion.ErrNoVersionInfo) {
					noInfo++
				} else if err == nil {
					components = append(components, componentFromPE(path, info))
				}
				done++
				if done%5000 == 0 {
					logf("  extracted from %d of %d files (%s elapsed)",
						done, len(paths), time.Since(start).Round(time.Second))
				}
				mu.Unlock()
			}
		}()
	}

	for _, p := range paths {
		select {
		case <-ctx.Done():
			close(queue)
			wg.Wait()
			return components, opened, noInfo
		case queue <- p:
		}
	}
	close(queue)
	wg.Wait()

	logf("extracted %d components from %d files in %s (%d had no version resource)",
		len(components), opened, time.Since(start).Round(time.Second), noInfo)
	return components, opened, noInfo
}

// componentFromRegistry turns one uninstall entry into a component.
//
// purl stays empty deliberately. There is no canonical PURL type for an
// uninstall-key row, and inventing pkg:generic/windows/... would create false
// confidence: a vulnerability scanner would silently match nothing against it
// rather than reporting that it could not.
func componentFromRegistry(e arp.Entry) model.Component {
	c := model.Component{
		Name:    e.DisplayName,
		Version: e.DisplayVersion,
		Type:    typeWindows,
		Vendor:  e.Publisher,
		FoundBy: registryCataloger,
		Attributes: attributes(map[string]string{
			"registry_key": e.Key,
			"scope":        string(e.Scope),
			"install_date": e.InstallDate,
		}),
	}
	if e.InstallLocation != "" {
		c.Locations = []string{e.InstallLocation}
	}
	if e.SystemComponent {
		c.Attributes["system_component"] = "true"
	}
	if e.WindowsInstaller {
		// For an MSI product the registry key is the product code, which is
		// the most stable identity Windows offers.
		c.Attributes["windows_installer"] = "true"
		c.Attributes["product_code"] = e.Key
	}
	return c
}

// componentFromPE turns an extracted version resource into a component.
func componentFromPE(path string, info peversion.Info) model.Component {
	name := firstNonEmpty(info.ProductName, info.OriginalFilename, baseName(path))

	version := preferredVersion(info.FileVersion, info.FixedFileVersion)

	return model.Component{
		Name:      name,
		Version:   version,
		Type:      typeBinary,
		Vendor:    info.CompanyName,
		Locations: []string{path},
		FoundBy:   peCataloger,
		Attributes: attributes(map[string]string{
			"file_version":       info.FileVersion,
			"product_version":    info.ProductVersion,
			"fixed_file_version": info.FixedFileVersion,
			"file_description":   info.FileDescription,
			"original_filename":  info.OriginalFilename,
		}),
	}
}

// attributes drops empty values, so that a key being present means something
// was actually recorded rather than that a field exists.
func attributes(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out[k] = v
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func baseName(path string) string {
	if i := strings.LastIndexByte(path, '\\'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// collectPackages adds Store and MSIX packages.
//
// A failure here is a warning, not an error: the uninstall inventory above is
// still correct and useful, and refusing to report it because one more source
// was unreadable would be the wrong trade.
func collectPackages(res *Result, logf func(string, ...any)) {
	packages, err := appx.ReadPackages()
	if err != nil {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("Store and MSIX packages could not be read (%v); software installed "+
				"from the Microsoft Store is missing from this inventory", err))
		return
	}

	for _, p := range packages {
		res.Components = append(res.Components, model.Component{
			Name:      p.Name,
			Version:   p.Version,
			Type:      typeMSIX,
			FoundBy:   appxCataloger,
			Locations: locationsOf(p.RootFolder),
			Attributes: attributes(map[string]string{
				"package_full_name": p.FullName,
				"architecture":      p.Architecture,
				"publisher_id":      p.PublisherID,
				"scope":             "user",
			}),
		})
	}
	res.Stats.Packages = len(packages)
	logf("appx: %d Store and MSIX packages", len(packages))

	// Said once, plainly. Store apps are installed per user and this registry
	// is HKCU, so a scan running as a service account reports that account's
	// packages and no one else's.
	if len(packages) > 0 {
		res.Warnings = append(res.Warnings,
			"Store and MSIX packages were read for the account running this scan only; "+
				"packages installed by other users are not listed")
	}
}

// collectUpdates adds the Windows updates the component store records.
func collectUpdates(res *Result, logf func(string, ...any)) {
	updates, err := appx.ReadUpdates()
	if err != nil {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("installed Windows updates could not be read (%v); the patch level "+
				"of this host is not in this inventory", err))
		return
	}

	for _, u := range updates {
		res.Components = append(res.Components, model.Component{
			// No version. An update is identified by its KB number and has no
			// version of its own; putting the host build here would attach a
			// fact about the machine to a row about an update.
			Name:    u.KB,
			Type:    typeHotfix,
			Vendor:  "Microsoft Corporation",
			FoundBy: updateCataloger,
			Attributes: attributes(map[string]string{
				"component_packages": strconv.Itoa(u.Components),
			}),
		})
	}
	res.Stats.Updates = len(updates)
	logf("updates: %d installed (from the component store)", len(updates))
}

func locationsOf(path string) []string {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return []string{path}
}
