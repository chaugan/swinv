package output

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Syft's CycloneDX decoder -- what Grype uses for `grype sbom:` -- reads the
// Linux release only from a components[] entry of type "operating-system".
// Without it every deb and rpm arrives with no distro, and Grype falls back to
// matching backported versions against upstream numbering.
func TestCycloneDXCarriesTheDistroWhereGrypeLooks(t *testing.T) {
	r := serviceReport()
	r.Host.OSPrettyName = "Ubuntu 26.04 LTS"

	var buf bytes.Buffer
	if err := WriteCycloneDX(&buf, r); err != nil {
		t.Fatalf("WriteCycloneDX: %v", err)
	}
	var doc struct {
		Components []struct {
			Type       string                         `json:"type"`
			Name       string                         `json:"name"`
			Version    string                         `json:"version"`
			Properties []struct{ Name, Value string } `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	var found bool
	for _, c := range doc.Components {
		if c.Type != "operating-system" {
			continue
		}
		found = true
		if c.Name != "ubuntu" || c.Version != "26.04" {
			t.Errorf("os component = %s@%s, want ubuntu@26.04", c.Name, c.Version)
		}
		props := map[string]string{}
		for _, p := range c.Properties {
			props[p.Name] = p.Value
		}
		for k, want := range map[string]string{
			"syft:distro:id":         "ubuntu",
			"syft:distro:versionID":  "26.04",
			"syft:distro:prettyName": "Ubuntu 26.04 LTS",
		} {
			if props[k] != want {
				t.Errorf("%s = %q, want %q", k, props[k], want)
			}
		}
	}
	if !found {
		t.Error("no operating-system component; a consumer reading this SBOM gets no distro")
	}
}

// A report with no distro -- a Windows host, or a tree with no os-release --
// must not gain an empty operating-system component claiming one.
func TestCycloneDXOmitsTheDistroWhenThereIsNone(t *testing.T) {
	r := serviceReport()
	r.Host.OSID = ""
	r.Host.OSVersionID = ""

	var buf bytes.Buffer
	if err := WriteCycloneDX(&buf, r); err != nil {
		t.Fatalf("WriteCycloneDX: %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte(`"operating-system"`)) {
		t.Error("emitted an operating-system component for a host with no distro")
	}
}
