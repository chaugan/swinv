//go:build windows

package appx

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	// appxRepository is where Windows records the packages installed for this
	// user. The machine-wide AppxAllUserStore key lists only *provisioned*
	// packages -- six against fifty-three on a test machine -- which is what
	// is available to install, not what is installed.
	appxRepository = `Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages`

	// cbsPackages is the component store: one key per component per update.
	cbsPackages = `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`
)

func readPackages() ([]Package, error) {
	root, err := registry.OpenKey(registry.CURRENT_USER, appxRepository, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("appx: opening the package repository: %w", err)
	}
	defer root.Close()

	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("appx: listing packages: %w", err)
	}

	out := make([]Package, 0, len(names))
	for _, name := range names {
		p, ok := parseFullName(name)
		if !ok {
			continue
		}
		if isResourcePackage(p.Architecture) {
			continue
		}

		// PackageRootFolder is the only value here worth reading. DisplayName
		// is an unresolved resource reference -- literally
		// "@{...?ms-resource://.../AppxManifest_DisplayName}" -- which needs
		// SHLoadIndirectString and a loaded package context to turn into text.
		// The package name is already a usable identity, so that is not worth
		// a COM call and a failure mode.
		if sub, err := registry.OpenKey(root, name, registry.QUERY_VALUE); err == nil {
			if folder, _, err := sub.GetStringValue("PackageRootFolder"); err == nil {
				p.RootFolder = strings.TrimSpace(folder)
			}
			sub.Close()
		}

		if isOperatingSystemApp(p.RootFolder) {
			continue
		}
		out = append(out, p)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].FullName < out[j].FullName })
	return out, nil
}

func readUpdates() ([]Update, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, cbsPackages, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("appx: opening the component store: %w", err)
	}
	defer root.Close()

	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("appx: listing component store packages: %w", err)
	}

	// Keyed by what identifies each stream: a KB where one exists, the kind
	// and version otherwise. Several thousand child packages collapse onto a
	// handful of updates this way.
	collected := make(map[string]*Update)

	for _, name := range names {
		pkg, ok := parseServicingPackage(name)
		if !ok {
			continue
		}

		state, ok := packageState(root, name)
		if !ok || !isInstalledState(state) {
			// Superseded and staged packages stay in the store long after they
			// stop describing the machine.
			continue
		}

		key := pkg.KB
		if key == "" {
			key = string(pkg.Kind) + " " + pkg.Version
		}

		if existing, ok := collected[key]; ok {
			existing.Components++
			continue
		}
		collected[key] = &Update{
			Kind:       pkg.Kind,
			KB:         pkg.KB,
			Version:    pkg.Version,
			Identity:   pkg.Identity,
			Pending:    isPendingState(state),
			Components: 1,
		}
	}

	out := make([]Update, 0, len(collected))
	for _, u := range collected {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].KB != out[j].KB {
			return out[i].KB < out[j].KB
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

// packageState reads a package's CurrentState. A key whose state cannot be
// read is treated as not installed: claiming an update is present on the
// strength of a key name is exactly the mistake this exists to correct.
func packageState(root registry.Key, name string) (uint64, bool) {
	k, err := registry.OpenKey(root, name, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()

	state, _, err := k.GetIntegerValue("CurrentState")
	if err != nil {
		return 0, false
	}
	return state, true
}
