package service

import (
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

func TestContainerComponents(t *testing.T) {
	got := ContainerComponents([]model.Container{{
		ID:    "9d5a98d0dc04ca4435668f83ff17cb7225536f2ca81d15aaaaaaaaaaaaaaaaaa",
		Name:  "notprem",
		State: "running",
		Image: &model.Image{
			Ref:            "nginxinc/nginx-unprivileged:1.27-alpine",
			ManifestDigest: "sha256:abc",
		},
		Services: []model.Service{{
			Executable: "/usr/sbin/nginx",
			Components: []string{"pkg:apk/alpine/nginx@1.27.5-r1?arch=x86_64&distro=alpine-3.21.3"},
		}},
	}})

	if len(got) != 1 {
		t.Fatalf("got %d components", len(got))
	}
	c := got[0]
	if c.Name != "nginx" || c.Version != "1.27.5-r1" || c.Type != "apk" {
		t.Errorf("component = %+v", c)
	}
	// The root keeps it separate from anything the host has at the same
	// version, which is the whole reason Root participates in identity.
	if c.Root != "container:9d5a98d0dc04" {
		t.Errorf("root = %q", c.Root)
	}
	// Only the packages owning a listening executable were probed, so these
	// rows are not the container's inventory and must not be read as one.
	if c.Attributes["scan_scope"] != "listening-executables-only" {
		t.Errorf("scan_scope = %q", c.Attributes["scan_scope"])
	}
	if c.Attributes["container_image"] != "nginxinc/nginx-unprivileged:1.27-alpine" {
		t.Errorf("container_image = %q", c.Attributes["container_image"])
	}
	// The same key the runtime route sets, or a consumer filtering on it drops
	// the more precisely identified half of the two.
	if c.Attributes["container_state"] != "running" {
		t.Errorf("container_state = %q", c.Attributes["container_state"])
	}
}

// A service with no resolved package contributes nothing rather than a
// component with no version, which would match no advisory and look like one
// that did.
func TestContainerComponentsSkipsUnidentified(t *testing.T) {
	got := ContainerComponents([]model.Container{{
		ID:       "aaa",
		Services: []model.Service{{Executable: "/usr/local/bin/node"}},
	}})
	if len(got) != 0 {
		t.Errorf("got %d components, want none: %+v", len(got), got)
	}
}

func TestParsePURL(t *testing.T) {
	cases := []struct {
		in                 string
		name, version, typ string
		ok                 bool
	}{
		{"pkg:apk/alpine/nginx@1.27.5-r1?arch=x86_64", "nginx", "1.27.5-r1", "apk", true},
		{"pkg:deb/debian/bash@5.2.15-2%2Bb7", "bash", "5.2.15-2%2Bb7", "deb", true},
		{"pkg:rpm/rhel/bash@4.4.20-6.el8_10?arch=x86_64&distro=rhel-8.10", "bash", "4.4.20-6.el8_10", "rpm", true},
		{"pkg:apk/busybox@1.37.0", "busybox", "1.37.0", "apk", true},
		// Not something a matcher can use, and not something to invent a
		// component from.
		{"pkg:oci/nginx@sha256%3Aabc?repository_url=x", "nginx", "sha256%3Aabc", "oci", true},
		{"pkg:apk/alpine/nginx", "", "", "", false},
		{"not-a-purl", "", "", "", false},
		{"", "", "", "", false},
	}
	for _, c := range cases {
		name, version, typ, ok := parsePURL(c.in)
		if ok != c.ok || name != c.name || version != c.version || typ != c.typ {
			t.Errorf("parsePURL(%q) = (%q, %q, %q, %v), want (%q, %q, %q, %v)",
				c.in, name, version, typ, ok, c.name, c.version, c.typ, c.ok)
		}
	}
}
