package ctrpkg

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, root, name, body string) {
	t.Helper()
	full := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func debianRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n")
	write(t, root, "var/lib/dpkg/info/nginx.list", "/.\n/usr/sbin/nginx\n/etc/nginx/nginx.conf\n")
	write(t, root, "var/lib/dpkg/info/coreutils.list", "/usr/bin/ls\n")
	write(t, root, "var/lib/dpkg/status", `Package: nginx
Status: install ok installed
Architecture: amd64
Version: 1.22.1-9

Package: coreutils
Status: install ok installed
Architecture: amd64
Version: 9.1-1
`)
	return root
}

// The identity a vulnerability matcher can actually use, for a service running
// inside a container: the container's own package, at the container's own
// distribution.
func TestProbeDebian(t *testing.T) {
	root := debianRoot(t)
	rel := ReadRelease(root)
	if rel.ID != "debian" || rel.VersionID != "12" {
		t.Fatalf("ReadRelease = %+v", rel)
	}

	got := Probe(root, []string{"/usr/sbin/nginx", "/opt/vendor/app"}, rel)
	owner, ok := got["/usr/sbin/nginx"]
	if !ok {
		t.Fatalf("nginx not attributed: %+v", got)
	}
	if owner.Name != "nginx" || owner.Version != "1.22.1-9" || owner.Type != "deb" {
		t.Errorf("owner = %+v", owner)
	}
	want := "pkg:deb/debian/nginx@1.22.1-9?arch=amd64&distro=debian-12"
	if owner.PURL != want {
		t.Errorf("PURL = %q, want %q", owner.PURL, want)
	}

	// Software the container's own package manager did not install is a
	// finding, not a failure, and must stay distinguishable from one it did.
	if _, ok := got["/opt/vendor/app"]; ok {
		t.Errorf("/opt/vendor/app was attributed to %+v", got["/opt/vendor/app"])
	}
}

// The container has its own /usr merge, independent of the host's.
func TestProbeDebianAcrossTheUsrMerge(t *testing.T) {
	root := debianRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	write(t, root, "var/lib/dpkg/info/netcat-openbsd.list", "/bin/nc.openbsd\n")
	write(t, root, "var/lib/dpkg/status", `Package: netcat-openbsd
Status: install ok installed
Architecture: amd64
Version: 1.226-1
`)

	got := Probe(root, []string{"/usr/bin/nc.openbsd"}, ReadRelease(root))
	if owner, ok := got["/usr/bin/nc.openbsd"]; !ok || owner.Name != "netcat-openbsd" {
		t.Errorf("owner = %+v, ok = %v", owner, ok)
	}
}

// A multi-arch package's list is named "foo:amd64.list" but its status stanza
// says "foo".
func TestProbeDebianMultiArchListName(t *testing.T) {
	root := debianRoot(t)
	write(t, root, "var/lib/dpkg/info/libssl3:amd64.list", "/usr/lib/x86_64-linux-gnu/libssl.so.3\n")
	write(t, root, "var/lib/dpkg/status", `Package: libssl3
Status: install ok installed
Architecture: amd64
Version: 3.0.11-1
`)
	got := Probe(root, []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"}, ReadRelease(root))
	if owner, ok := got["/usr/lib/x86_64-linux-gnu/libssl.so.3"]; !ok || owner.Name != "libssl3" {
		t.Errorf("owner = %+v, ok = %v", owner, ok)
	}
}

func TestProbeAlpine(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=alpine\nVERSION_ID=3.21.7\n")
	write(t, root, "lib/apk/db/installed", `C:Q1abc
P:busybox
V:1.37.0-r14
A:x86_64
F:bin
R:busybox
R:sh

C:Q1def
P:nginx
V:1.26.2-r0
A:x86_64
F:usr/sbin
R:nginx
`)

	rel := ReadRelease(root)
	got := Probe(root, []string{"/bin/busybox", "/usr/sbin/nginx"}, rel)

	if owner := got["/bin/busybox"]; owner.Name != "busybox" || owner.Version != "1.37.0-r14" {
		t.Errorf("busybox owner = %+v", owner)
	}
	want := "pkg:apk/alpine/nginx@1.26.2-r0?arch=x86_64&distro=alpine-3.21.7"
	if owner := got["/usr/sbin/nginx"]; owner.PURL != want {
		t.Errorf("nginx PURL = %q, want %q", owner.PURL, want)
	}
}

// Nothing to read is the ordinary case -- a distroless or scratch image has no
// package database at all -- and must be silence, not an error and not a guess.
func TestProbeEmptyRoot(t *testing.T) {
	root := t.TempDir()
	if got := Probe(root, []string{"/app/server"}, Release{}); got != nil {
		t.Errorf("Probe on an empty root = %v, want nil", got)
	}
	if got := ReadRelease(root); got.ID != "" {
		t.Errorf("ReadRelease on an empty root = %+v", got)
	}
	if got := Probe(root, nil, Release{}); got != nil {
		t.Errorf("Probe with no paths = %v, want nil", got)
	}
}

// A PURL missing its version matches nothing, so it is better not emitted.
func TestPURLRequiresAVersion(t *testing.T) {
	if got := purl("deb", Release{ID: "debian"}, "nginx", "", "amd64"); got != "" {
		t.Errorf("purl with no version = %q, want empty", got)
	}
	// And an unknown distribution still yields a usable type-and-name PURL.
	if got := purl("deb", Release{}, "nginx", "1.0", ""); got != "pkg:deb/nginx@1.0" {
		t.Errorf("purl = %q", got)
	}
}

// RPM prints no epoch when there is none; emitting "0:" produces a version
// string that fails to match every advisory.
func TestRPMVersion(t *testing.T) {
	zero, three := 0, 3
	cases := []struct {
		epoch            *int
		version, release string
		want             string
	}{
		{nil, "4.4.20", "6.el8_10", "4.4.20-6.el8_10"},
		{&zero, "4.4.20", "6.el8_10", "4.4.20-6.el8_10"},
		{&three, "1.2", "1.el9", "3:1.2-1.el9"},
		{nil, "1.2", "", "1.2"},
	}
	for _, c := range cases {
		if got := rpmVersion(c.epoch, c.version, c.release); got != c.want {
			t.Errorf("rpmVersion(%v, %q, %q) = %q, want %q", c.epoch, c.version, c.release, got, c.want)
		}
	}
}
