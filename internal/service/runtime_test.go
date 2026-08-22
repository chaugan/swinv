package service

import (
	"strings"
	"testing"

	"github.com/chaugan/swinv/internal/ctrpkg"
	"github.com/chaugan/swinv/internal/dockerapi"
	"github.com/chaugan/swinv/internal/model"
)

// "No containers" has two causes that produce identical output: a runtime that
// answered and had nothing, and a runtime that was never reached. A Windows
// run reported zero on a machine with eight stopped containers, and nothing in
// the report distinguished that from a broken pipe.
func TestRuntimeStatusWarning(t *testing.T) {
	reached := RuntimeStatus{Reached: true, Endpoint: `\\.\pipe\docker_engine`}
	if w := reached.Warning(); !strings.Contains(w, "reported no containers") {
		t.Errorf("a reachable but empty runtime said %q", w)
	}
	// Most machines run no containers at all, and saying so on every one of
	// them would be noise rather than information.
	if w := (RuntimeStatus{}).Warning(); w != "" {
		t.Errorf("an absent runtime produced %q", w)
	}
	if w := (RuntimeStatus{Reached: true, Found: 3}).Warning(); w != "" {
		t.Errorf("a runtime with containers produced %q", w)
	}
}

// A declared port is what the image says it serves on. It is never an
// observation, and for a stopped container it is all there is.
func TestDeclaredEndpoints(t *testing.T) {
	got := declaredEndpoints(dockerapi.Container{
		Exposed: []dockerapi.PortMapping{
			{ContainerPort: 9200, Protocol: "tcp"},
			{ContainerPort: 9300, Protocol: "tcp"},
		},
		Ports: []dockerapi.PortMapping{
			{ContainerPort: 9200, Protocol: "tcp", HostPort: 19200},
		},
	})
	if len(got) != 2 || got[0] != "9200/tcp" || got[1] != "9300/tcp" {
		t.Errorf("declaredEndpoints = %v", got)
	}
	if got := declaredEndpoints(dockerapi.Container{}); len(got) != 0 {
		t.Errorf("a container with no ports declared %v", got)
	}
}

// Packages read from a whole container database are not the same claim as a
// package that owns a listening executable, and the scope says which.
func TestPackageComponentsRecordTheirScope(t *testing.T) {
	got := packageComponents(model.Container{
		ID:    "f6e3203743df0000000000000000000000000000000000000000000000000000",
		Name:  "argilla-argilla-1",
		State: "exited",
		Image: &model.Image{Ref: "argilla/argilla-server:latest", ManifestDigest: "sha256:abc"},
	}, []ctrpkg.Owner{
		{Name: "openssl", Version: "3.0.15", Type: "deb", PURL: "pkg:deb/debian/openssl@3.0.15"},
		{Name: "nopurl", Version: "1"},
	})

	if len(got) != 1 {
		t.Fatalf("got %d components, want only the one with a PURL", len(got))
	}
	c := got[0]
	if c.Root != "container:f6e3203743df" {
		t.Errorf("root = %q", c.Root)
	}
	if c.Attributes["scan_scope"] != "container-package-database" {
		t.Errorf("scan_scope = %q", c.Attributes["scan_scope"])
	}
	// The state matters to a consumer: a stopped container is software present
	// on the machine, not software currently serving.
	if c.Attributes["container_state"] != "exited" {
		t.Errorf("container_state = %q", c.Attributes["container_state"])
	}
	if c.Attributes["container_image_digest"] != "sha256:abc" {
		t.Errorf("container_image_digest = %q", c.Attributes["container_image_digest"])
	}
}

func TestImagePURLIsALocator(t *testing.T) {
	got := imagePURL("nginxinc/nginx-unprivileged:1.27-alpine", "sha256:abc")
	want := "pkg:oci/nginx-unprivileged@sha256%3Aabc?repository_url=nginxinc/nginx-unprivileged&tag=1.27-alpine"
	if got != want {
		t.Errorf("imagePURL =\n%q\nwant\n%q", got, want)
	}
	// A locally built image that was never pushed has no digest, and inventing
	// one would produce a value matching nobody else's record of it.
	if got := imagePURL("coremap26-frontend", ""); got != "pkg:oci/coremap26-frontend?repository_url=coremap26-frontend" {
		t.Errorf("imagePURL = %q", got)
	}
	if got := imagePURL("", "sha256:abc"); got != "" {
		t.Errorf("imagePURL with no reference = %q", got)
	}
}
