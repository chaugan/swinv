//go:build linux

package configsurface

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	uid := os.Getuid()
	write("etc/passwd",
		"root:x:0:0:root:/root:/bin/bash\n"+
			"svc:x:999:999::/var/lib/svc:/usr/sbin/nologin\n"+
			fmt.Sprintf("alice:x:%d:%d::/home/alice:/bin/bash\n", uid, uid), 0o644)
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

// The security fix (#R2): a symlink from an attacker-owned authorized_keys to
// a root-only file must not be read into the inventory. readOwnedByCapped
// refuses it because the resolved file is owned by root, not the account.
func TestSSHKeysRejectSymlinkToOtherOwner(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "home/alice/.ssh"), 0o755); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"),
		[]byte(fmt.Sprintf("alice:x:%d:%d::/home/alice:/bin/bash\n", uid, uid)), 0o644); err != nil {
		t.Fatal(err)
	}
	// A regular key file owned by the runner (== alice here) is read.
	good := filepath.Join(root, "home/alice/.ssh/authorized_keys")
	if err := os.WriteFile(good, []byte("ssh-ed25519 AAAA alice@host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Collect(context.Background(), Options{Root: root, Scope: ScopeStandard, IncludeCommands: true})
	if n := len(entriesByKind(got)[model.ConfigKindSSHKey]); n != 1 {
		t.Fatalf("expected the legitimate key to be read, got %d", n)
	}

	// A FIFO in place of the key file must be refused (would hang a root read).
	root2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root2, "home/alice/.ssh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root2, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root2, "etc/passwd"),
		[]byte(fmt.Sprintf("alice:x:%d:%d::/home/alice:/bin/bash\n", uid, uid)), 0o644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root2, "home/alice/.ssh/authorized_keys")
	if err := syscallMkfifo(fifo); err != nil {
		t.Skipf("cannot create fifo: %v", err)
	}
	done := make(chan int, 1)
	go func() {
		got := Collect(context.Background(), Options{Root: root2, Scope: ScopeStandard, IncludeCommands: true})
		done <- len(entriesByKind(got)[model.ConfigKindSSHKey])
	}()
	select {
	case n := <-done:
		if n != 0 {
			t.Errorf("a FIFO authorized_keys produced %d entries; the read should have been refused", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Collect hung on a FIFO authorized_keys - the regular-file gate did not hold")
	}
}

func syscallMkfifo(path string) error {
	return mkfifo(path)
}
