//go:build linux

package configsurface

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

func TestLinuxExtras(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string, mode os.FileMode) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}

	write("etc/sudoers", "# comment\nroot ALL=(ALL:ALL) ALL\ndeploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n", 0o440)
	write("etc/passwd",
		"root:x:0:0:root:/root:/bin/bash\n"+
			"svc:x:999:999::/var/lib/svc:/usr/sbin/nologin\n"+
			"alice:x:1000:1000::/home/alice:/bin/bash\n", 0o644)
	write("home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAAC3Nz alice@work\n", 0o600)
	write("etc/ld.so.preload", "/opt/evil/hook.so\n", 0o644)
	write("etc/modules-load.d/custom.conf", "# load these\nvboxdrv\n", 0o644)
	write("etc/profile.d/lang.sh", "export LANG=C\n", 0o644)

	got := entriesByKind(Collect(context.Background(),
		Options{Root: root, Scope: ScopeStandard, IncludeCommands: true}))

	if n := len(got[model.ConfigKindSudoRule]); n != 2 {
		t.Errorf("sudo rules = %d, want 2: %+v", n, got[model.ConfigKindSudoRule])
	}
	var nopasswd *model.ConfigEntry
	for i := range got[model.ConfigKindSudoRule] {
		if got[model.ConfigKindSudoRule][i].Name == "deploy" {
			nopasswd = &got[model.ConfigKindSudoRule][i]
		}
	}
	if nopasswd == nil || len(nopasswd.Evidence) == 0 {
		t.Fatalf("the NOPASSWD grant was not flagged: %+v", nopasswd)
	}

	// Only uid 0 and login accounts; the nologin svc account is dropped.
	accts := got[model.ConfigKindAccount]
	if len(accts) != 2 {
		t.Errorf("accounts = %d, want 2 (root + alice, svc dropped): %+v", len(accts), accts)
	}

	keys := got[model.ConfigKindSSHKey]
	if len(keys) != 1 || keys[0].User != "alice" {
		t.Errorf("ssh keys = %+v", keys)
	}

	pre := got[model.ConfigKindPreload]
	if len(pre) != 1 || pre[0].Executable != "/opt/evil/hook.so" {
		t.Errorf("preload = %+v", pre)
	}

	mods := got[model.ConfigKindKernelModule]
	if len(mods) != 1 || mods[0].Name != "vboxdrv" {
		t.Errorf("modules = %+v", mods)
	}

	if len(got[model.ConfigKindShellInit]) != 1 {
		t.Errorf("shell-init = %+v", got[model.ConfigKindShellInit])
	}
}

func TestSSHKeyParsing(t *testing.T) {
	if sshKeyType("ssh-ed25519 AAAAC3Nz... user@host") != "ssh-ed25519" {
		t.Error("key type not extracted")
	}
	if sshKeyComment("ssh-rsa AAAAB3... alice@laptop") != "alice@laptop" {
		t.Error("comment not extracted")
	}
	if sshKeyComment("ssh-rsa AAAAB3...") != "unnamed key" {
		t.Error("a commentless key should read as unnamed")
	}
}
