//go:build windows

package arp

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const uninstallPath = `Software\Microsoft\Windows\CurrentVersion\Uninstall`

type hive struct {
	key   registry.Key
	path  string
	scope Scope
	// access carries the WOW64 flag. A 64-bit process reading HKLM\Software
	// sees only native-bitness entries; 32-bit installs live under
	// WOW6432Node and are missed entirely unless asked for explicitly.
	access uint32
}

func read() ([]Entry, error) {
	hives := []hive{
		{registry.LOCAL_MACHINE, uninstallPath, ScopeMachine, registry.READ | registry.WOW64_64KEY},
		{registry.LOCAL_MACHINE, uninstallPath, ScopeMachine32, registry.READ | registry.WOW64_32KEY},
		{registry.CURRENT_USER, uninstallPath, ScopeUser, registry.READ},
	}

	var (
		out  []Entry
		errs []string
	)
	for _, h := range hives {
		entries, err := readHive(h)
		if err != nil {
			// A missing hive is normal: WOW6432Node does not exist on a 32-bit
			// system, and a user hive may hold no uninstall key at all. Record
			// it and carry on rather than failing the whole read.
			errs = append(errs, fmt.Sprintf("%s: %v", h.scope, err))
			continue
		}
		out = append(out, entries...)
	}

	if len(out) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("arp: no uninstall keys could be read (%s)", strings.Join(errs, "; "))
	}
	return out, nil
}

func readHive(h hive) ([]Entry, error) {
	root, err := registry.OpenKey(h.key, h.path, h.access)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	out := make([]Entry, 0, len(names))
	for _, name := range names {
		sub, err := registry.OpenKey(root, name, h.access)
		if err != nil {
			// An entry can be removed between listing and opening, and some
			// keys deny access. Neither is a reason to abandon the hive.
			continue
		}
		e, ok := readEntry(sub, name, h.scope)
		sub.Close()
		if ok {
			out = append(out, e)
		}
	}
	return out, nil
}

func readEntry(k registry.Key, name string, scope Scope) (Entry, bool) {
	display := strValue(k, "DisplayName")
	if strings.TrimSpace(display) == "" {
		// No display name means a placeholder or an orphaned key, not software.
		return Entry{}, false
	}

	return Entry{
		Key:              name,
		Scope:            scope,
		DisplayName:      display,
		DisplayVersion:   strValue(k, "DisplayVersion"),
		Publisher:        strValue(k, "Publisher"),
		InstallLocation:  strings.TrimRight(strValue(k, "InstallLocation"), `\`),
		InstallDate:      strValue(k, "InstallDate"),
		SystemComponent:  intValue(k, "SystemComponent") == 1,
		WindowsInstaller: intValue(k, "WindowsInstaller") == 1,
	}, true
}

// strValue reads a string value, tolerating REG_EXPAND_SZ and a wrong type.
// A value that is absent or unreadable is an empty string, never an error:
// these keys are written by thousands of unrelated installers and are
// inconsistent in every way a registry value can be.
func strValue(k registry.Key, name string) string {
	if s, _, err := k.GetStringValue(name); err == nil {
		if expanded, err := registry.ExpandString(s); err == nil {
			return strings.TrimSpace(expanded)
		}
		return strings.TrimSpace(s)
	}
	return ""
}

func intValue(k registry.Key, name string) uint64 {
	if v, _, err := k.GetIntegerValue(name); err == nil {
		return v
	}
	return 0
}
