package scan

import (
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
