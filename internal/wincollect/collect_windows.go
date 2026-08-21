//go:build windows

package wincollect

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chaugan/swinv/internal/arp"
	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/peversion"
	"github.com/chaugan/swinv/internal/usn"
)

// Cataloger names, which appear in each component's found_by and are how a
// consumer tells where a fact came from.
const (
	registryCataloger = "windows-registry-cataloger"
	peCataloger       = "windows-pe-cataloger"
)

// Component types. Registry entries get "windows"; extracted executables reuse
// "binary", which already means the same thing on Linux.
const (
	typeWindows = "windows"
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
			// Neither is fatal to the run: the registry inventory above still
			// stands, and saying so is more useful than refusing to report it.
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"%s was not enumerated (%v); software there that the registry does not "+
					"record is missing from this inventory", volume, err))
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
				"%d files under %s\\Windows and WindowsApps were not inventoried: operating "+
					"system components and Store apps need the component-store and Appx "+
					"catalogers, which do not exist yet", osOrStore, volume))
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
