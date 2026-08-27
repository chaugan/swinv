//go:build linux

package configsurface

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

// fixtureRoot builds a small tree with one of everything: a system crontab,
// a cron.d file, a daily script (world-writable, deliberately), a shadowed
// systemd unit, a timer, and a SUID binary.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string, mode os.FileMode) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		// umask-proof: the mode is the point of the fixture.
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}

	write("etc/crontab", "0 3 * * * root /usr/local/bin/rotate.sh\n", 0o644)
	write("etc/cron.d/vendor", "@reboot agent /opt/vendor/agent --start\n", 0o644)
	write("etc/cron.daily/cleanup", "#!/bin/sh\nrm -rf /tmp/x\n", 0o777)
	write("var/spool/cron/crontabs/alice", "*/5 * * * * /home/alice/sync.sh\n", 0o600)

	write("usr/lib/systemd/system/thing.service",
		"[Service]\nExecStart=/usr/lib/thing/thingd --stale\n", 0o644)
	write("etc/systemd/system/thing.service",
		"[Service]\nUser=thing\nExecStart=/usr/bin/thingd --etc-wins\n", 0o644)
	write("usr/lib/systemd/system/apt-daily.timer",
		"[Timer]\nOnCalendar=*-*-* 6,18:00\n", 0o644)
	write("usr/lib/systemd/system/apt-daily.service",
		"[Service]\nExecStart=/usr/lib/apt/apt-helper wait-online\n", 0o644)

	write("usr/bin/sudo-like", "#!/bin/sh\n", 0o755|os.ModeSetuid)
	write("usr/bin/plain", "#!/bin/sh\n", 0o755)
	return root
}

func entriesByKind(entries []model.ConfigEntry) map[string][]model.ConfigEntry {
	out := map[string][]model.ConfigEntry{}
	for _, e := range entries {
		out[e.Kind] = append(out[e.Kind], e)
	}
	return out
}

func TestCollectLinux(t *testing.T) {
	root := fixtureRoot(t)
	got := Collect(context.Background(), Options{Root: root, Scope: ScopeStandard, IncludeCommands: true})
	byKind := entriesByKind(got)

	if n := len(byKind[model.ConfigKindCron]); n != 4 {
		t.Fatalf("got %d cron entries, want 4: %+v", n, byKind[model.ConfigKindCron])
	}

	// The world-writable daily script is the joinable weakness: a root job
	// anyone can edit.
	var daily *model.ConfigEntry
	for i := range got {
		if got[i].Path == "/etc/cron.daily/cleanup" {
			daily = &got[i]
		}
	}
	if daily == nil {
		t.Fatal("the cron.daily script was not collected")
	}
	if daily.Schedule != "@daily" || daily.User != "root" {
		t.Errorf("daily = %+v", daily)
	}
	if !daily.WorldWritable {
		t.Error("a mode 0777 script run by root was not marked world-writable")
	}

	services := byKind[model.ConfigKindSystemdService]
	var thing *model.ConfigEntry
	for i := range services {
		if services[i].Name == "thing.service" {
			thing = &services[i]
		}
	}
	if thing == nil {
		t.Fatal("thing.service was not collected")
	}
	if thing.Path != "/etc/systemd/system/thing.service" {
		t.Errorf("path = %q; /etc must shadow /usr/lib, the way systemd resolves it", thing.Path)
	}
	if thing.User != "thing" || thing.Executable != "/usr/bin/thingd" {
		t.Errorf("thing = %+v", thing)
	}

	timers := byKind[model.ConfigKindSystemdTimer]
	if len(timers) != 1 {
		t.Fatalf("got %d timers, want 1", len(timers))
	}
	tm := timers[0]
	if tm.Schedule != "OnCalendar=*-*-* 6,18:00" {
		t.Errorf("timer schedule = %q", tm.Schedule)
	}
	if tm.Executable != "/usr/lib/apt/apt-helper" {
		t.Errorf("the timer did not resolve its service's executable: %+v", tm)
	}

	suid := byKind[model.ConfigKindSUID]
	if len(suid) != 1 {
		t.Fatalf("got %d suid entries, want 1: %+v", len(suid), suid)
	}
	if suid[0].Path != "/usr/bin/sudo-like" || !suid[0].SetUID || suid[0].Mode != "4755" {
		t.Errorf("suid = %+v", suid[0])
	}
}

func TestCollectOffCollectsNothing(t *testing.T) {
	if got := Collect(context.Background(), Options{Root: fixtureRoot(t), Scope: ScopeOff}); got != nil {
		t.Fatalf("scope off collected %d entries", len(got))
	}
}

func TestExecutablePathsAndOwners(t *testing.T) {
	entries := []model.ConfigEntry{
		{Executable: "/usr/bin/thingd"},
		{Executable: "/usr/bin/thingd"}, // dedup
		{Executable: "relative-name"},   // not probeable
	}
	paths := ExecutablePaths(entries)
	if len(paths) != 1 || paths[0] != "/usr/bin/thingd" {
		t.Fatalf("paths = %v", paths)
	}
	AttachOwners(entries, map[string][]string{"/usr/bin/thingd": {"pkg:deb/debian/thing@1.0"}})
	if entries[0].PURL != "pkg:deb/debian/thing@1.0" || entries[1].PURL != "pkg:deb/debian/thing@1.0" {
		t.Errorf("owners not attached: %+v", entries[:2])
	}
}
