//go:build linux

package configsurface

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/pathnorm"
)

// suidDirs is the standard-scope SUID walk, the same population the ELF
// probe walks: where the distribution and operators put binaries. ScopeAll
// walks the whole root instead, which is what finds the one dropped in
// /var/tmp - and costs a filesystem walk to do it.
var suidDirs = []string{
	"/usr/bin", "/usr/sbin", "/usr/libexec", "/usr/lib",
	"/usr/local/bin", "/usr/local/sbin", "/usr/local/lib",
	"/opt", "/srv",
}

// maxSUIDWalk bounds the ScopeAll walk the way the ELF walk is bounded: a
// runaway filesystem must degrade the answer, not the machine.
const maxSUIDWalk = 2_000_000

// Collect reads the configuration surface of the tree at opts.Root.
func Collect(ctx context.Context, opts Options) []model.ConfigEntry {
	if opts.Scope == ScopeOff {
		return nil
	}
	root := opts.Root
	if root == "" {
		root = "/"
	}

	var out []model.ConfigEntry
	out = append(out, collectCron(root, opts.IncludeCommands)...)
	out = append(out, collectSystemd(root, opts.IncludeCommands)...)
	out = append(out, collectSUID(ctx, opts, root, opts.Scope)...)

	for i := range out {
		markWorldWritable(root, &out[i])
	}
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

// under joins a report-relative path onto the scan root for reading.
func under(root, p string) string {
	return filepath.Join(root, filepath.FromSlash(p))
}

func collectCron(root string, includeCommands bool) []model.ConfigEntry {
	var out []model.ConfigEntry

	if raw, err := os.ReadFile(under(root, "/etc/crontab")); err == nil { // #nosec G304 -- fixed path under the scan root
		out = append(out, parseCrontab(string(raw), "/etc/crontab", "root", true, includeCommands)...)
	}
	if names, err := os.ReadDir(under(root, "/etc/cron.d")); err == nil {
		for _, de := range names {
			if de.IsDir() {
				continue
			}
			p := "/etc/cron.d/" + de.Name()
			if raw, err := os.ReadFile(under(root, p)); err == nil { // #nosec G304 -- enumerated under the scan root
				out = append(out, parseCrontab(string(raw), p, "root", true, includeCommands)...)
			}
		}
	}
	// Per-user spools: the filename is the user.
	if names, err := os.ReadDir(under(root, "/var/spool/cron/crontabs")); err == nil {
		for _, de := range names {
			if de.IsDir() {
				continue
			}
			p := "/var/spool/cron/crontabs/" + de.Name()
			if raw, err := os.ReadFile(under(root, p)); err == nil { // #nosec G304 -- enumerated under the scan root
				out = append(out, parseCrontab(string(raw), p, de.Name(), false, includeCommands)...)
			}
		}
	}
	// The periodic directories: every executable file is a job, and the
	// directory is its schedule.
	for _, period := range []string{"hourly", "daily", "weekly", "monthly"} {
		dir := "/etc/cron." + period
		names, err := os.ReadDir(under(root, dir))
		if err != nil {
			continue
		}
		for _, de := range names {
			if de.IsDir() {
				continue
			}
			p := dir + "/" + de.Name()
			e := model.ConfigEntry{
				Kind:       model.ConfigKindCron,
				Name:       de.Name(),
				Path:       p,
				User:       "root",
				Schedule:   "@" + period,
				Executable: p,
				Attack:     "T1053.003",
			}
			if includeCommands {
				e.Command = p
			}
			out = append(out, e)
		}
	}
	return out
}

// unitDirs in precedence order: a unit in /etc shadows the same name in
// /run, which shadows /usr/lib - the same rule systemd applies.
var unitDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system"}

func collectSystemd(root string, includeCommands bool) []model.ConfigEntry {
	// name -> report-relative path, first (highest-precedence) dir wins.
	units := map[string]string{}
	for _, dir := range unitDirs {
		names, err := os.ReadDir(under(root, dir))
		if err != nil {
			continue
		}
		for _, de := range names {
			name := de.Name()
			if de.IsDir() {
				continue
			}
			if !strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer") {
				continue
			}
			if _, shadowed := units[name]; !shadowed {
				units[name] = dir + "/" + name
			}
		}
	}

	parsed := map[string]unitFile{}
	for name, p := range units {
		raw, err := os.ReadFile(under(root, p)) // #nosec G304 -- enumerated under the scan root
		if err != nil {
			continue
		}
		parsed[name] = parseUnit(string(raw))
	}

	var out []model.ConfigEntry
	for name, p := range units {
		u := parsed[name]
		switch {
		case strings.HasSuffix(name, ".timer"):
			// The entry describes the pair: the timer's schedule and the
			// command of the service it triggers.
			target := u.Unit
			if target == "" {
				target = strings.TrimSuffix(name, ".timer") + ".service"
			}
			e := model.ConfigEntry{
				Kind:     model.ConfigKindSystemdTimer,
				Name:     name,
				Path:     p,
				Schedule: u.Schedule,
				Attack:   "T1053.006",
			}
			if svc, ok := parsed[target]; ok {
				e.User = defaultRoot(svc.User)
				e.Executable = firstExecutable(svc.ExecStart)
				if includeCommands {
					e.Command = svc.ExecStart
				}
			}
			out = append(out, e)

		case u.ExecStart != "":
			e := model.ConfigEntry{
				Kind:       model.ConfigKindSystemdService,
				Name:       name,
				Path:       p,
				User:       defaultRoot(u.User),
				Executable: firstExecutable(u.ExecStart),
				Attack:     "T1543.002",
			}
			if includeCommands {
				e.Command = u.ExecStart
			}
			out = append(out, e)
		}
	}
	return out
}

func defaultRoot(user string) string {
	if user == "" {
		return "root"
	}
	return user
}

func collectSUID(ctx context.Context, opts Options, root, scope string) []model.ConfigEntry {
	dirs := suidDirs
	if scope == ScopeAll {
		dirs = []string{"/"}
	}
	excluded := pathnorm.SubtreeExcludes(opts.Excludes)

	// Kernel-backed and ephemeral trees have no SUID binaries worth a walk,
	// and /proc in particular is bottomless.
	skip := map[string]bool{"proc": true, "sys": true, "dev": true, "run": true}

	var out []model.ConfigEntry
	seen := 0
	for _, dir := range dirs {
		base := under(root, dir)
		_ = filepath.WalkDir(base, func(path string, de fs.DirEntry, err error) error {
			if err != nil {
				return nil // an unreadable subtree degrades the answer, never the walk
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			rel := strings.TrimPrefix(path, strings.TrimSuffix(root, "/"))
			if !strings.HasPrefix(rel, "/") {
				rel = "/" + rel
			}
			if de.IsDir() {
				if scope == ScopeAll {
					if top, rerr := filepath.Rel(base, path); rerr == nil && skip[top] {
						return fs.SkipDir
					}
				}
				if excluded != nil && excluded(rel) {
					return fs.SkipDir
				}
			}
			seen++
			if seen > maxSUIDWalk {
				return fs.SkipAll
			}
			if de.IsDir() || !de.Type().IsRegular() {
				return nil
			}
			info, err := de.Info()
			if err != nil {
				return nil
			}
			mode := info.Mode()
			if mode&(os.ModeSetuid|os.ModeSetgid) == 0 {
				return nil
			}
			out = append(out, model.ConfigEntry{
				Kind:       model.ConfigKindSUID,
				Name:       filepath.Base(path),
				Path:       rel,
				Executable: rel,
				Mode:       fmt.Sprintf("%04o", mode.Perm()|setuidBits(mode)),
				SetUID:     mode&os.ModeSetuid != 0,
				SetGID:     mode&os.ModeSetgid != 0,
				Attack:     "T1548.001",
			})
			return nil
		})
	}
	return out
}

// setuidBits maps Go's mode bits back onto the octal a Unix reader expects:
// 4000 for setuid, 2000 for setgid.
func setuidBits(mode os.FileMode) os.FileMode {
	var b os.FileMode
	if mode&os.ModeSetuid != 0 {
		b |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		b |= 0o2000
	}
	return b
}
