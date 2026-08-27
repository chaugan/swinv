//go:build windows

package configsurface

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/chaugan/swinv/internal/model"
)

// Collect reads the Windows configuration surface: Scheduled Tasks and the
// Run/RunOnce autoruns. The SUID walk has no Windows meaning and the systemd
// kinds have no Windows existence; the Defender-exclusions and services rows
// from issue #13 are the next slice.
func Collect(ctx context.Context, opts Options) []model.ConfigEntry {
	if opts.Scope == ScopeOff {
		return nil
	}

	var out []model.ConfigEntry
	out = append(out, collectScheduledTasks(ctx, opts.IncludeCommands)...)
	out = append(out, collectAutoruns(opts.IncludeCommands)...)

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// collectScheduledTasks reads the task XML files directly. The Task
// Scheduler's own store is these files; reading them needs no COM, no
// service calls, and works identically on a mounted image.
func collectScheduledTasks(ctx context.Context, includeCommands bool) []model.ConfigEntry {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	base := filepath.Join(sysRoot, "System32", "Tasks")

	var out []model.ConfigEntry
	_ = filepath.WalkDir(base, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtrees degrade the answer, never the walk
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if de.IsDir() || !de.Type().IsRegular() {
			return nil
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- enumerated under the Tasks store
		if err != nil {
			return nil
		}
		name, _ := filepath.Rel(base, path)
		out = append(out, parseScheduledTask(raw, `\`+name, path, includeCommands)...)
		return nil
	})
	return out
}

// autorunKeys are the machine-scope Run keys. Per-user hives are the next
// slice: enumerating HKU means deciding about unloaded hives, and the
// machine keys are the higher-signal start.
var autorunKeys = []struct {
	root registry.Key
	path string
	name string
}{
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
}

func collectAutoruns(includeCommands bool) []model.ConfigEntry {
	var out []model.ConfigEntry
	for _, k := range autorunKeys {
		key, err := registry.OpenKey(k.root, k.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, err := key.ReadValueNames(0)
		if err != nil {
			_ = key.Close()
			continue
		}
		for _, name := range names {
			command, _, err := key.GetStringValue(name)
			if err != nil || strings.TrimSpace(command) == "" {
				continue
			}
			e := model.ConfigEntry{
				Kind:       model.ConfigKindAutorun,
				Name:       name,
				Path:       k.name,
				Executable: windowsExecutable(command),
				Attack:     "T1547.001",
			}
			if includeCommands {
				e.Command = command
			}
			out = append(out, e)
		}
		_ = key.Close()
	}

	// The all-users Startup folder is the file half of the same technique.
	if pd := os.Getenv("ProgramData"); pd != "" {
		dir := filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs\StartUp`)
		if names, err := os.ReadDir(dir); err == nil {
			for _, de := range names {
				if de.IsDir() || strings.EqualFold(de.Name(), "desktop.ini") {
					continue
				}
				p := filepath.Join(dir, de.Name())
				e := model.ConfigEntry{
					Kind:       model.ConfigKindAutorun,
					Name:       de.Name(),
					Path:       p,
					Executable: p,
					Attack:     "T1547.001",
				}
				if includeCommands {
					e.Command = p
				}
				out = append(out, e)
			}
		}
	}
	return out
}
