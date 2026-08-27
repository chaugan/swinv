//go:build windows

package wincollect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chaugan/swinv/internal/appx"
	"github.com/chaugan/swinv/internal/arp"
	"github.com/chaugan/swinv/internal/langpkg"
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
	languageCataloger = "language-manifest-cataloger"
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

	var toOpen, manifests []string
	for _, volume := range volumes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		start := time.Now()
		enumerated, err := usn.Enumerate(ctx, usn.Options{
			Volume: volume,
			Keep: func(name string, isDir bool, _ uint32) bool {
				// Manifests cost nothing extra to discover: the MFT record is
				// already in hand, and only the ones that survive filtering
				// are ever opened.
				return !isDir && (isExecutable(name) || langpkg.IsManifest(name))
			},
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

		// "executable files", spelled out: an operator reading "executables"
		// concluded the walk was skipping DLLs, when DLLs are most of what
		// it finds.
		logf("%s: %d executable files (exe, dll, sys, ocx, cpl, drv) from %d MFT records in %s",
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
			// OS and Store territory is deliberately left out of the
			// import-probe list, by the same rule the extractor applies: the
			// operating system is represented by its updates, not file by
			// file, and probing 50,000 System32 DLLs answers no question a
			// consumer asks. They still appear as links - resolved, marked
			// os_component - whenever a product's binary actually loads one.
			if isExecutable(e.Name) && !OSOrStoreTerritory(e.Path, volume) {
				res.Executables = append(res.Executables, e.Path)
			}
			if OSOrStoreTerritory(e.Path, volume) {
				osOrStore++
				continue
			}
			// Language-ecosystem manifests are a separate stream. They are not
			// attributed to a registry product, because nothing on Windows
			// installs Python or npm packages through a system package
			// manager -- which is also why every one found here is genuinely
			// upstream and should be assessed as such.
			if kind := langpkg.Classify(e.Path); kind != "" {
				manifests = append(manifests, e.Path)
				continue
			}
			if !isExecutable(e.Name) {
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

	// --- 4a. language ecosystems ------------------------------------------
	collectLanguagePackages(res, manifests, logf)

	// --- 4b. extract ------------------------------------------------------
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
		CPEs:    candidateCPEs(e.Publisher, e.DisplayName, e.DisplayVersion),
		FoundBy: registryCataloger,
		Attributes: attributes(map[string]string{
			"registry_key": e.Key,
			"scope":        string(e.Scope),
			"install_date": e.InstallDate,
		}),
	}
	// Every directory this entry points at, not only InstallLocation.
	//
	// The recovered ones were already being computed and handed to the
	// coverage set, so a product whose only clue is its UninstallString had
	// its files treated as accounted for -- and therefore never opened by the
	// full scan -- while its component carried no location for anything to
	// join against. Mosquitto came out of a full scan of a real machine with
	// a registry entry, no location, no PE component, and a listening socket
	// on 1883 that nothing could name. Blocked in both directions by the same
	// asymmetry.
	c.Locations = InstallLocations(e.InstallLocation, e.DisplayIcon, e.UninstallString)
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
		CPEs:      candidateCPEs(info.CompanyName, name, version),
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
			Name:    p.Name,
			Version: p.Version,
			Type:    typeMSIX,
			// An Appx package name is dotted, and its first component is
			// conventionally the publisher: "Microsoft.WindowsTerminal". The
			// registry records only a publisher *hash*, so this is the only
			// vendor string available.
			CPEs:      candidateCPEs(appxPublisher(p.Name), p.Name, p.Version),
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
		res.Components = append(res.Components, componentFromUpdate(u))
	}
	res.Stats.Updates = len(updates)
	logf("updates: %d installed servicing packages", len(updates))

	// A machine that has installed an update but not yet rebooted is running
	// the previous patch level while the store describes the next one. An
	// unattended scan lands in that window regularly, and a report that does
	// not say so overstates how patched the host is.
	for _, u := range updates {
		if u.Pending {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"%s is installed but not active until this host reboots; the running "+
					"system is still on the previous patch level", describeUpdate(u)))
		}
	}
}

func locationsOf(path string) []string {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return []string{path}
}

// componentFromUpdate turns a servicing package into a component.
//
// The name says which stream it belongs to rather than repeating a KB, because
// for cumulative and servicing-stack updates there is no KB -- Windows
// identifies them by version, and that version is the thing worth comparing
// against a patch-level baseline.
func componentFromUpdate(u appx.Update) model.Component {
	c := model.Component{
		Name:    describeUpdate(u),
		Version: u.Version,
		Type:    typeHotfix,
		Vendor:  "Microsoft Corporation",
		FoundBy: updateCataloger,
		Attributes: attributes(map[string]string{
			"servicing_stream":   string(u.Kind),
			"package_identity":   u.Identity,
			"component_packages": strconv.Itoa(u.Components),
			"kb":                 u.KB,
		}),
	}
	if u.Pending {
		c.Attributes["reboot_pending"] = "true"
	}
	return c
}

// describeUpdate names an update the way an operator would.
func describeUpdate(u appx.Update) string {
	switch u.Kind {
	case appx.KindCumulative:
		return "Windows cumulative update"
	case appx.KindServicingStack:
		return "Windows servicing stack update"
	case appx.KindDotNetRollup:
		return ".NET Framework rollup"
	default:
		if u.KB != "" {
			return u.KB
		}
		return "Windows update"
	}
}

// appxPublisher takes the vendor from a dotted Appx package name.
//
// The package repository records a publisher hash rather than a name, so there
// is nothing else to use. Returns "" for a single-component name, which yields
// no CPE at all rather than one with a guessed vendor.
func appxPublisher(name string) string {
	if i := strings.Index(name, "."); i > 0 {
		return name[:i]
	}
	return ""
}

// collectLanguagePackages reads the ecosystem manifests enumeration found.
//
// This is the Windows answer to the forty catalogers Syft gives the Linux
// collector. Only two ecosystems are covered -- Python and npm -- because those
// are what gets installed machine-wide on Windows, and because each one here is
// a parser written and tested rather than a cataloger reused.
//
// Every file opened is one MFT enumeration already identified by name, so the
// same arrangement that keeps executable extraction to a fraction of the volume
// applies unchanged: nothing is opened to find out whether it is interesting.
func collectLanguagePackages(res *Result, manifests []string, logf func(string, ...any)) {
	if len(manifests) == 0 {
		return
	}

	var read, skipped int
	for _, path := range manifests {
		p, err := readManifest(path)
		switch {
		case err != nil && langpkg.NotAPackage(err):
			// Most package.json files under a project tree describe a project
			// rather than an installed package. Ordinary, and not worth a
			// warning apiece.
			skipped++
			continue
		case err != nil:
			skipped++
			continue
		}

		res.Components = append(res.Components, model.Component{
			Name:      p.Name,
			Version:   p.Version,
			Type:      p.Type,
			Language:  p.Language,
			Vendor:    p.Author,
			PURL:      langpkg.PURL(p),
			CPEs:      candidateCPEs(p.Author, p.Name, p.Version),
			Locations: []string{path},
			FoundBy:   languageCataloger,
		})
		read++
	}

	res.Stats.LanguagePackages = read
	logf("language packages: %d read from %d manifests (%d were not installed packages)",
		read, len(manifests), skipped)
}

// readManifest opens one manifest and parses it according to its kind.
func readManifest(path string) (langpkg.Package, error) {
	kind := langpkg.Classify(path)
	if kind == "" {
		return langpkg.Package{}, fmt.Errorf("wincollect: %s is not a manifest", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return langpkg.Package{}, err
	}
	defer f.Close()

	var p langpkg.Package
	switch kind {
	case langpkg.TypePython:
		p, err = langpkg.ParsePythonMetadata(f)
	case langpkg.TypeNPM:
		p, err = langpkg.ParsePackageJSON(f)
	}
	if err != nil {
		return langpkg.Package{}, err
	}
	p.Path = path
	return p, nil
}
