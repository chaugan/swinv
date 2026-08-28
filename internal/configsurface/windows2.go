//go:build windows

package configsurface

import (
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/chaugan/swinv/internal/model"
)

// The second Windows slice (#13): Defender exclusions - the highest-signal
// single item on either list, an exclusion over a writable directory is a
// standing invitation invisible to every version scanner - plus the services
// registry, Image File Execution Options debuggers, and AppInit_DLLs. All
// registry reads, no COM, no elevation beyond what a full inventory already
// assumes.

func collectWindowsExtras(includeCommands bool) []model.ConfigEntry {
	var out []model.ConfigEntry
	out = append(out, collectDefenderExclusions()...)
	out = append(out, collectServices(includeCommands)...)
	out = append(out, collectIFEO(includeCommands)...)
	out = append(out, collectAppInit()...)
	return out
}

func collectDefenderExclusions() []model.ConfigEntry {
	base := `SOFTWARE\Microsoft\Windows Defender\Exclusions`
	kinds := map[string]string{
		"Paths":      "path",
		"Extensions": "extension",
		"Processes":  "process",
	}
	var out []model.ConfigEntry
	for sub, what := range kinds {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+sub, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, _ := key.ReadValueNames(0)
		for _, name := range names {
			e := model.ConfigEntry{
				Kind:     model.ConfigKindAVException,
				Name:     name,
				Path:     `HKLM\` + base + `\` + sub,
				Attack:   "T1562.001",
				Evidence: []string{"Defender " + what + " exclusion"},
			}
			if what == "path" {
				e.Executable = name
			}
			out = append(out, e)
		}
		_ = key.Close()
	}
	return out
}

func collectServices(includeCommands bool) []model.ConfigEntry {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	names, err := root.ReadSubKeyNames(0)
	if err != nil {
		return nil
	}
	var out []model.ConfigEntry
	for _, name := range names {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\`+name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		image, _, _ := sk.GetStringValue("ImagePath")
		_ = sk.Close()
		image = strings.TrimSpace(image)
		if image == "" {
			continue
		}
		e := model.ConfigEntry{
			Kind:       model.ConfigKindService,
			Name:       name,
			Path:       `HKLM\SYSTEM\CurrentControlSet\Services\` + name,
			Executable: windowsExecutable(expandImagePath(image)),
			Attack:     "T1543.003",
		}
		if includeCommands {
			e.Command = image
		}
		out = append(out, e)
	}
	return out
}

// expandImagePath drops the \??\ NT-path prefix and any leading service
// switches so the executable resolves and joins.
func expandImagePath(image string) string {
	image = strings.TrimPrefix(image, `\??\`)
	image = strings.TrimPrefix(image, `\SystemRoot\`)
	return image
}

// collectIFEO reads Image File Execution Options: a Debugger value hijacks
// the named program's launch, and a GlobalFlag can silently attach one.
func collectIFEO(includeCommands bool) []model.ConfigEntry {
	base := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	names, err := root.ReadSubKeyNames(0)
	if err != nil {
		return nil
	}
	var out []model.ConfigEntry
	for _, name := range names {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		debugger, _, _ := sk.GetStringValue("Debugger")
		_ = sk.Close()
		if strings.TrimSpace(debugger) == "" {
			continue // only the hijacked entries are worth a record
		}
		e := model.ConfigEntry{
			Kind:       model.ConfigKindIFEO,
			Name:       name,
			Path:       `HKLM\` + base + `\` + name,
			Executable: windowsExecutable(debugger),
			Attack:     "T1546.012",
			Evidence:   []string{"launching " + name + " runs this debugger instead"},
		}
		// The debugger command line rides the same redaction switch as every
		// other command line; it was set unconditionally, silently defeating
		// --no-service-command on this one field.
		if includeCommands {
			e.Command = debugger
		}
		out = append(out, e)
	}
	return out
}

// collectAppInit reads AppInit_DLLs, loaded into every process that links
// user32 when the mechanism is enabled.
func collectAppInit() []model.ConfigEntry {
	var out []model.ConfigEntry
	for _, base := range []string{
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
	} {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		dlls, _, _ := key.GetStringValue("AppInit_DLLs")
		enabled, _, _ := key.GetIntegerValue("LoadAppInit_DLLs")
		_ = key.Close()
		for _, dll := range strings.FieldsFunc(dlls, func(r rune) bool { return r == ',' || r == ' ' }) {
			dll = strings.TrimSpace(dll)
			if dll == "" {
				continue
			}
			ev := "AppInit DLL"
			if enabled == 0 {
				ev += " (LoadAppInit_DLLs disabled)"
			}
			out = append(out, model.ConfigEntry{
				Kind:       model.ConfigKindAppInit,
				Name:       dll,
				Path:       `HKLM\` + base,
				Executable: windowsExecutable(dll),
				Attack:     "T1546.010",
				Evidence:   []string{ev},
			})
		}
	}
	return out
}
