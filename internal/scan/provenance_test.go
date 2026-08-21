package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

// The PURL below is verbatim from a downstream report: a Debian 12 openssl
// found inside a nested root, stamped with the scanning host's Ubuntu 26.04.
func TestStripDistroClaim(t *testing.T) {
	cases := map[string]string{
		"pkg:deb/ubuntu/openssl@3.0.11-1~deb12u2?arch=amd64&distro=ubuntu-26.04": "pkg:deb/openssl@3.0.11-1~deb12u2?arch=amd64",
		"pkg:deb/ubuntu/bash@5.2.15-2?distro=ubuntu-26.04":                       "pkg:deb/bash@5.2.15-2",
		"pkg:rpm/fedora/openssl@3.2.1?arch=x86_64&distro=fedora-43":              "pkg:rpm/openssl@3.2.1?arch=x86_64",
		"pkg:apk/alpine/musl@1.2.5?arch=x86_64&distro=alpine-3.22":               "pkg:apk/musl@1.2.5?arch=x86_64",

		// Ecosystems with a meaningful namespace and no distro claim are left
		// alone in every respect that matters -- these never reach this
		// function, because they are not distro packages, but the transform
		// must not mangle them if they did.
		"pkg:generic/openssl@3.0.11":        "pkg:generic/openssl@3.0.11",
		"pkg:golang/example.com/mod@v1.2.3": "pkg:golang/mod@v1.2.3",

		// Not a PURL, or nothing to strip.
		"":                    "",
		"not-a-purl":          "not-a-purl",
		"pkg:deb/openssl@1.0": "pkg:deb/openssl@1.0",
	}
	for in, want := range cases {
		if got := stripDistroClaim(in); got != want {
			t.Errorf("stripDistroClaim(%q)\n  got  %q\n  want %q", in, got, want)
		}
	}
}

func TestRootOf(t *testing.T) {
	nested := []string{"/snap/core18/2999", "/var/lib/docker/overlay2/abc/diff"}

	cases := map[string]string{
		"/snap/core18/2999/var/lib/dpkg/status":            "/snap/core18/2999",
		"/var/lib/docker/overlay2/abc/diff/usr/bin/python": "/var/lib/docker/overlay2/abc/diff",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3":            hostRoot,
		"/snap/core20/1234/usr/bin/git":                    hostRoot, // a root we were not told about

		// The boundary that matters: a sibling path must not match by prefix.
		"/snap/core18/29990/usr/bin/git": hostRoot,
	}
	for loc, want := range cases {
		if got := rootOf([]string{loc}, nested); got != want {
			t.Errorf("rootOf(%q) = %q, want %q", loc, got, want)
		}
	}

	if got := rootOf(nil, nested); got != hostRoot {
		t.Errorf("rootOf(nil) = %q, want %q", got, hostRoot)
	}
}

// TestAssignRootsKeepsSameNamedPackagesApart is the reported defect: a package
// in a snap base and the host's own copy deduplicated into one row whose
// locations spanned both roots, so a consumer could not tell which root either
// belonged to -- and that decides whose advisories apply.
func TestAssignRootsKeepsSameNamedPackagesApart(t *testing.T) {
	nested := []string{"/snap/core18/2999"}
	in := []model.Component{
		{
			Name: "openssl", Version: "3.0.11-1~deb12u2", Type: "deb",
			PURL:      "pkg:deb/ubuntu/openssl@3.0.11-1~deb12u2?arch=amd64&distro=ubuntu-26.04",
			Locations: []string{"/snap/core18/2999/var/lib/dpkg/status"},
		},
		{
			Name: "openssl", Version: "3.0.11-1~deb12u2", Type: "deb",
			PURL:      "pkg:deb/ubuntu/openssl@3.0.11-1~deb12u2?arch=amd64&distro=ubuntu-26.04",
			Locations: []string{"/usr/share/doc/libssl3t64/copyright"},
		},
	}

	out := model.Normalize(assignRoots(in, nested))

	if len(out) != 2 {
		t.Fatalf("got %d components, want 2: different roots are different installs", len(out))
	}
	for _, c := range out {
		if len(c.Locations) != 1 {
			t.Errorf("%s in %s has locations from %d roots: %v", c.Name, c.Root, len(c.Locations), c.Locations)
		}
		switch c.Root {
		case "/snap/core18/2999":
			if got := c.PURL; got != "pkg:deb/openssl@3.0.11-1~deb12u2?arch=amd64" {
				t.Errorf("nested component still claims a distribution: %q", got)
			}
		case hostRoot:
			if c.PURL != "pkg:deb/ubuntu/openssl@3.0.11-1~deb12u2?arch=amd64&distro=ubuntu-26.04" {
				t.Errorf("the host's own package lost its distro claim: %q", c.PURL)
			}
		default:
			t.Errorf("unexpected root %q", c.Root)
		}
	}
}

// TestNestedRootPrefixRecognisesBaseSnaps pins a reported gap: 862 components
// under /snap/ all reported root "/", so a consumer assessed an Ubuntu 18.04
// package set against the host's 26.04 advisories.
func TestNestedRootPrefixRecognisesBaseSnaps(t *testing.T) {
	cases := map[string]string{
		"/snap/core18/2999/usr/share/snappy/dpkg.yaml":         "/snap/core18/2999",
		"/snap/core20/2866/usr/share/snappy/dpkg.yaml":         "/snap/core20/2866",
		"/snap/gnome-3-28-1804/198/usr/share/snappy/dpkg.yaml": "/snap/gnome-3-28-1804/198",

		// Still detected by the databases already known.
		"/mnt/image/var/lib/dpkg/status": "/mnt/image",
	}
	for loc, want := range cases {
		got, ok := nestedRootPrefix(loc)
		if !ok || got != want {
			t.Errorf("nestedRootPrefix(%q) = %q, %v; want %q, true", loc, got, ok, want)
		}
	}

	// The scanned host's own databases are not nested roots.
	for _, loc := range []string{"/var/lib/dpkg/status", "/usr/share/snappy/dpkg.yaml"} {
		if _, ok := nestedRootPrefix(loc); ok {
			t.Errorf("nestedRootPrefix(%q) reported the host as nested", loc)
		}
	}
}

// Once a base snap is a root, everything in it is attributed there -- not only
// the package database that revealed it.
func TestAssignRootsCoversTheWholeSnap(t *testing.T) {
	nested := []string{"/snap/core18/2999"}
	in := []model.Component{
		{Name: "python3-cryptography", Type: "deb",
			PURL:      "pkg:deb/ubuntu/python3-cryptography@2.1.4-1ubuntu1.4%2Besm1?distro=ubuntu-26.04",
			Locations: []string{"/snap/core18/2999/usr/share/snappy/dpkg.yaml"}},
		{Name: "cryptography", Type: "python",
			PURL:      "pkg:pypi/cryptography@2.1.4",
			Locations: []string{"/snap/core18/2999/usr/lib/python3/dist-packages/cryptography-2.1.4.egg-info/PKG-INFO"}},
	}

	out := assignRoots(in, nested)
	for _, c := range out {
		if c.Root != "/snap/core18/2999" {
			t.Errorf("%s has root %q, want the snap", c.Name, c.Root)
		}
	}
	// And the snap's deb no longer claims the host's distribution.
	if strings.Contains(out[0].PURL, "distro=") || strings.Contains(out[0].PURL, "/ubuntu/") {
		t.Errorf("a package inside an 18.04 base still claims the 26.04 host: %q", out[0].PURL)
	}
}

// TestAssignRootsRecordsTheRootsOwnRelease: a consumer was inferring the
// release from the directory name -- core18 meaning Ubuntu 18.04 -- which is a
// naming convention rather than a fact. The root states it.
func TestAssignRootsRecordsTheRootsOwnRelease(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "snap", "core18", "2999")
	if err := os.MkdirAll(filepath.Join(snap, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	osRelease := "ID=ubuntu\nVERSION_ID=\"18.04\"\nPRETTY_NAME=\"Ubuntu 18.04.6 LTS\"\n"
	if err := os.WriteFile(filepath.Join(snap, "etc", "os-release"), []byte(osRelease), 0o644); err != nil {
		t.Fatal(err)
	}

	in := []model.Component{
		{Name: "cryptography", Type: "python",
			Locations: []string{filepath.Join(snap, "usr/lib/python3/dist-packages/cryptography-2.1.4.egg-info/PKG-INFO")}},
		{Name: "openssl", Type: "deb", Locations: []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"}},
	}

	out := assignRoots(in, []string{snap})

	if got := out[0].Attributes["root_os_id"]; got != "ubuntu" {
		t.Errorf("root_os_id = %q, want ubuntu", got)
	}
	if got := out[0].Attributes["root_os_version_id"]; got != "18.04" {
		t.Errorf("root_os_version_id = %q, want 18.04 -- the snap's release, not the host's", got)
	}
	// The host's own components must not be labelled with a nested release.
	if _, ok := out[1].Attributes["root_os_id"]; ok {
		t.Errorf("a host component was given a nested root's release: %v", out[1].Attributes)
	}
}

// A root that states no release reports none, rather than a guess.
func TestAssignRootsWithoutAnOSRelease(t *testing.T) {
	dir := t.TempDir()
	layer := filepath.Join(dir, "layer")
	if err := os.MkdirAll(layer, 0o755); err != nil {
		t.Fatal(err)
	}

	out := assignRoots([]model.Component{
		{Name: "x", Locations: []string{filepath.Join(layer, "usr/bin/x")}},
	}, []string{layer})

	if _, ok := out[0].Attributes["root_os_id"]; ok {
		t.Errorf("a root with no os-release produced one: %v", out[0].Attributes)
	}
	if out[0].Root != layer {
		t.Errorf("Root = %q, want %q", out[0].Root, layer)
	}
}
