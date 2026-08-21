package scan

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
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
	want := map[string]string{
		"/usr/sbin/sshd": "/usr/sbin/sshd",
		"/usr/bin/bash":  "usr/bin/bash",
		"/usr/bin/node":  "/usr/lib/../bin/node",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("probeSet = %v, want %v", got, want)
	}
	if probeSet(nil, identity) != nil {
		t.Error("probeSet(nil) should be nil, so resolveOwners can skip the work entirely")
	}
}

// The two sides disagree about the same file on every merged-/usr system:
// dpkg on Ubuntu 24.04 says netcat-openbsd owns /bin/nc.openbsd, while
// /proc/<pid>/exe reports /usr/bin/nc.openbsd. A plain comparison misses, and
// the running nc is reported as software no package manager installed.
func TestUsrMergeFoldsPreMergePaths(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"usr/bin", "usr/lib"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"bin", "lib"} {
		if err := os.Symlink("usr/"+d, filepath.Join(root, d)); err != nil {
			t.Fatal(err)
		}
	}
	// A real directory, as on Alpine: nothing to fold.
	if err := os.MkdirAll(filepath.Join(root, "sbin"), 0o755); err != nil {
		t.Fatal(err)
	}

	canon := usrMerge(root)
	cases := map[string]string{
		"/bin/nc.openbsd":      "/usr/bin/nc.openbsd",
		"/usr/bin/nc.openbsd":  "/usr/bin/nc.openbsd",
		"/lib/systemd/systemd": "/usr/lib/systemd/systemd",
		"/sbin/chronyd":        "/sbin/chronyd",
		"/opt/vendor/app":      "/opt/vendor/app",
		"/bin":                 "/bin",
		"relative":             "relative",
	}
	for in, want := range cases {
		if got := canon(in); got != want {
			t.Errorf("canon(%q) = %q, want %q", in, got, want)
		}
	}

	// And the probe answers under the name the caller asked about, not the
	// canonical one -- the caller looks the answer up by the path /proc gave.
	probe := probeSet([]string{"/usr/bin/nc.openbsd"}, canon)
	if probe["/usr/bin/nc.openbsd"] != "/usr/bin/nc.openbsd" {
		t.Errorf("probe = %v", probe)
	}
}

// On a system with no merge -- Alpine, or an old tree -- /bin/busybox and
// /usr/bin/busybox are different files, and folding them would invent a match.
func TestUsrMergeIsAStatNotAnAssumption(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"bin", "sbin", "lib", "usr/bin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	canon := usrMerge(root)
	if got := canon("/bin/busybox"); got != "/bin/busybox" {
		t.Errorf("canon(/bin/busybox) = %q on an unmerged tree", got)
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
