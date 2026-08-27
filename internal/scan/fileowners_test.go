package scan

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chaugan/swinv/internal/model"
)

// The join the whole services section rests on. A deb's recorded locations are
// its dpkg metadata files, never the binaries it installed, so without this
// every daemon on a stock server reports as software no package manager
// installed -- a confident wrong answer, in the direction that matters most.
func TestOwnerProbeResolvesAgainstThePackageFileList(t *testing.T) {
	root, err := filepath.Abs("../../testdata/rootfs")
	if err != nil {
		t.Fatalf("resolving fixture root: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	res, err := Run(ctx, Options{
		Root:       root,
		OwnerProbe: []string{"/usr/bin/openssl", "/usr/bin/bash", "/opt/vendor/appserver"},
	})
	if err != nil {
		t.Fatalf("scan.Run: %v", err)
	}

	got := res.FileOwners
	if len(got["/usr/bin/openssl"]) != 1 || got["/usr/bin/openssl"][0] != "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12" {
		t.Errorf("/usr/bin/openssl owners = %v", got["/usr/bin/openssl"])
	}
	if len(got["/usr/bin/bash"]) != 1 {
		t.Errorf("/usr/bin/bash owners = %v", got["/usr/bin/bash"])
	}
	// A probed path that no package claims must be absent, not present and
	// empty: "nothing installed this" is a finding, and it has to stay
	// distinguishable from "nobody asked".
	if _, ok := got["/opt/vendor/appserver"]; ok {
		t.Errorf("/opt/vendor/appserver has an entry: %v", got["/opt/vendor/appserver"])
	}
	// And a path outside the probe must never appear, which is what keeps the
	// cost proportional to the question rather than to the machine.
	if _, ok := got["/usr/lib/ssl/openssl.cnf"]; ok {
		t.Errorf("an unprobed path was indexed anyway")
	}
}

// Asking nothing must cost nothing and produce nothing.
func TestOwnerProbeIsAbsentWhenNotAsked(t *testing.T) {
	root, err := filepath.Abs("../../testdata/rootfs")
	if err != nil {
		t.Fatalf("resolving fixture root: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	res, err := Run(ctx, Options{Root: root})
	if err != nil {
		t.Fatalf("scan.Run: %v", err)
	}
	if res.FileOwners != nil {
		t.Errorf("FileOwners = %v, want nil when OwnerProbe is empty", res.FileOwners)
	}
}

func TestProbeSetNormalises(t *testing.T) {
	identity := func(p string) string { return p }
	got := probeSet([]string{" /usr/sbin/sshd ", "usr/bin/bash", "/usr/lib/../bin/node", ""}, identity)
	want := map[string][]string{
		"/usr/sbin/sshd": {"/usr/sbin/sshd"},
		"/usr/bin/bash":  {"usr/bin/bash"},
		"/usr/bin/node":  {"/usr/lib/../bin/node"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("probeSet = %v, want %v", got, want)
	}
	if probeSet(nil, identity) != nil {
		t.Error("probeSet(nil) should be nil, so resolveOwners can skip the work entirely")
	}
}

// A nested root's copy of a package must not be reported as owning a host
// path: the file the probe matched lives inside that tree, not on the host.
func TestFinalizeOwnersRefusesNestedRoots(t *testing.T) {
	components := []model.Component{
		{Name: "openssh-server", PURL: "pkg:deb/host@1", Root: "/"},
		{Name: "openssh-server", PURL: "pkg:deb/snap@1", Root: "/snap/core22/current"},
	}
	got := finalizeOwners(components, map[string][]int{"/usr/sbin/sshd": {0, 1}})
	if len(got["/usr/sbin/sshd"]) != 1 || got["/usr/sbin/sshd"][0] != "pkg:deb/host@1" {
		t.Errorf("owners = %v, want only the host's copy", got["/usr/sbin/sshd"])
	}

	// And a hit that is *only* a nested root leaves no entry at all, rather
	// than an empty one that would read as a positive answer.
	if got := finalizeOwners(components[1:], map[string][]int{"/usr/sbin/sshd": {0}}); got != nil {
		t.Errorf("finalizeOwners = %v, want nil", got)
	}
}

// Two callers spelling the same file differently - /bin/mount from a systemd
// unit, /usr/bin/mount from the SUID walk - must both get the answer. The
// map used to keep only the last asker, and the mount binary was reported as
// unowned SUID on a host where the mount package plainly owns it.
func TestProbeSetKeepsEverySpellingOfTheSameFile(t *testing.T) {
	usrMerge := func(p string) string {
		if strings.HasPrefix(p, "/bin/") {
			return "/usr" + p
		}
		return p
	}
	got := probeSet([]string{"/bin/mount", "/usr/bin/mount"}, usrMerge)
	want := map[string][]string{
		"/usr/bin/mount": {"/bin/mount", "/usr/bin/mount"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("probeSet = %v, want %v", got, want)
	}
}

// A probed path that is a symlink must also answer for its target: dpkg's
// md5sums cannot list a symlink, so the target is the only spelling the
// package metadata knows. /usr/bin/rm -> gnurm on Ubuntu's coreutils
// transition is the real case.
func TestExpandProbeSymlinksFollowsToTheRealFile(t *testing.T) {
	root := t.TempDir()
	if err := writeTree(root, map[string]string{"usr/bin/gnurm": "elf"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("gnurm", filepath.Join(root, "usr/bin/rm")); err != nil {
		t.Fatal(err)
	}

	identity := func(p string) string { return p }
	probe := probeSet([]string{"/usr/bin/rm"}, identity)
	expandProbeSymlinks(probe, root, identity)
	if !reflect.DeepEqual(probe["/usr/bin/gnurm"], []string{"/usr/bin/rm"}) {
		t.Fatalf("the symlink's target does not answer for the asked path: %v", probe)
	}
}

// An absolute symlink inside a scanned image must resolve inside the image.
func TestExpandProbeSymlinksStaysJailed(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Points at an absolute path that exists on the HOST but not in the root.
	if err := os.Symlink("/bin/sh", filepath.Join(root, "usr/bin/sh")); err != nil {
		t.Fatal(err)
	}
	identity := func(p string) string { return p }
	probe := probeSet([]string{"/usr/bin/sh"}, identity)
	expandProbeSymlinks(probe, root, identity)
	if len(probe) != 1 {
		t.Fatalf("an escaping symlink grew the probe: %v", probe)
	}
}

func writeTree(root string, files map[string]string) error {
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
			return err
		}
	}
	return nil
}
