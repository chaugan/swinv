package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

func exposureReport() *model.Report {
	r := serviceReport()
	r.Scan.RanAsRoot = true
	r.Scan.ExposureBlindSpots = []string{"netfilter-dnat-not-read", "firewall-rules-not-read"}
	r.Exposure = []model.Exposure{
		{
			Address: "0.0.0.0", Port: 22, Protocol: "tcp", Family: "ipv4",
			BindScope: model.BindWildcard, PID: 811, Executable: "/usr/sbin/sshd",
			Unit: "ssh.service", User: "0",
			Components: []string{"pkg:deb/ubuntu/openssh-server@10.2p1"},
			Confidence: model.ConfidenceHigh,
			Evidence:   []string{"socket 0.0.0.0:22/tcp held by pid 811"},
		},
		{
			Address: "0.0.0.0", Port: 3000, Protocol: "tcp", Family: "ipv4",
			BindScope: model.BindWildcard, PID: 2562, Executable: "/usr/bin/docker-proxy",
			Backend: &model.Backend{
				Address: "172.17.0.2", Port: 3000, Container: "df613448bf6a",
				Executable: "/usr/sbin/nginx", Via: "docker-proxy-argv",
			},
			Image:      &model.Image{Ref: "nginx:alpine", ManifestDigest: "sha256:abc"},
			Components: []string{"pkg:apk/alpine/nginx@1.27.5-r1"},
			Confidence: model.ConfidenceHigh,
		},
		{
			Address: "127.0.0.1", Port: 5432, Protocol: "tcp", Family: "ipv4",
			BindScope: model.BindLoopback, Confidence: model.ConfidenceLow,
		},
	}
	return r
}

func TestExposureCSVShape(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteExposureCSV(&buf, exposureReport()); err != nil {
		t.Fatalf("WriteExposureCSV: %v", err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want header + 3", len(rows))
	}
	if !reflect.DeepEqual(rows[0], exposureCSVColumns) {
		t.Errorf("header = %v", rows[0])
	}

	index := map[string]int{}
	for i, name := range exposureCSVColumns {
		index[name] = i
	}
	published := rows[2]
	if published[index["backend_container"]] != "df613448bf6a" {
		t.Errorf("backend_container = %q", published[index["backend_container"]])
	}
	if published[index["components"]] != "pkg:apk/alpine/nginx@1.27.5-r1" {
		t.Errorf("components = %q; the forwarder's own package must never appear here",
			published[index["components"]])
	}
	if published[index["image_manifest_digest"]] != "sha256:abc" {
		t.Errorf("image_manifest_digest = %q", published[index["image_manifest_digest"]])
	}

	// The scan-level qualifiers repeat on every row, because a consumer
	// reading only this file never sees the scan block and would otherwise be
	// unable to tell a complete row from a partial one.
	for _, row := range rows[1:] {
		if row[index["firewall_examined"]] != "false" {
			t.Errorf("firewall_examined = %q", row[index["firewall_examined"]])
		}
		if !strings.Contains(row[index["exposure_blind_spots"]], "netfilter-dnat-not-read") {
			t.Errorf("exposure_blind_spots = %q", row[index["exposure_blind_spots"]])
		}
		if row[index["ran_as_root"]] != "true" {
			t.Errorf("ran_as_root = %q", row[index["ran_as_root"]])
		}
	}
}

// The header alone says "we looked and found nothing exposed", which a missing
// file does not.
func TestExposureCSVAlwaysWritesTheHeader(t *testing.T) {
	r := exposureReport()
	r.Exposure = nil
	var buf bytes.Buffer
	if err := WriteExposureCSV(&buf, r); err != nil {
		t.Fatalf("WriteExposureCSV: %v", err)
	}
	if got := strings.Count(buf.String(), "\n"); got != 1 {
		t.Errorf("got %d lines, want just the header", got)
	}
}

// The exposure CSV enumerates its columns by hand, which is how the component
// NDJSON silently lost two fields.
func TestExposureCSVCarriesEveryField(t *testing.T) {
	columns := map[string]bool{}
	for _, c := range exposureCSVColumns {
		columns[c] = true
	}
	// Nested structs are flattened with a prefix; the rest map by snake case.
	renamed := map[string]string{
		"PID":                "pid",
		"BindScope":          "bind_scope",
		"WildcardCoversIPv4": "wildcard_covers_ipv4",
		"Backend":            "backend_address",
		"Image":              "image_ref",
	}

	et := reflect.TypeOf(model.Exposure{})
	for i := 0; i < et.NumField(); i++ {
		name := et.Field(i).Name
		want, ok := renamed[name]
		if !ok {
			want = snake(name)
		}
		if !columns[want] {
			t.Errorf("model.Exposure.%s has no %q column, so the exposure CSV silently omits it", name, want)
		}
	}
}

// CycloneDX has one services array, so the zone is what keeps a container's
// listener from reading as a host one. trustZone is used rather than
// x-trust-boundary, which is a boolean about consumer relationships and would
// produce wrong conclusions in tools this project does not control.
func TestCycloneDXTrustZones(t *testing.T) {
	r := exposureReport()
	r.Services = []model.Service{
		{Endpoints: []string{"0.0.0.0:22/tcp"}, Unit: "ssh.service", Confidence: model.ConfidenceHigh},
		{Endpoints: []string{"127.0.0.1:5432/tcp"}, Unit: "postgresql.service", Confidence: model.ConfidenceHigh},
	}
	r.Containers = []model.Container{{
		ID:   "9d5a98d0dc04ca4435668f83ff17cb7225536f2ca81d15aa",
		Name: "notprem",
		Services: []model.Service{{
			Endpoints: []string{"0.0.0.0:8080/tcp"}, Executable: "/usr/sbin/nginx",
			Processes: 9, PublishedAs: []string{"0.0.0.0:80/tcp"},
			Confidence: model.ConfidenceHigh,
		}},
	}}

	var buf bytes.Buffer
	if err := WriteCycloneDX(&buf, r); err != nil {
		t.Fatalf("WriteCycloneDX: %v", err)
	}
	var doc struct {
		Services []struct {
			Name       string                         `json:"name"`
			Group      string                         `json:"group"`
			TrustZone  string                         `json:"trustZone"`
			Properties []struct{ Name, Value string } `json:"properties"`
		} `json:"services"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Services) != 3 {
		t.Fatalf("got %d services, want 3", len(doc.Services))
	}

	zones := map[string]string{}
	groups := map[string]string{}
	for _, s := range doc.Services {
		zones[s.Name] = s.TrustZone
		groups[s.Name] = s.Group
	}
	if zones["ssh.service"] != "host-network" {
		t.Errorf("ssh trustZone = %q", zones["ssh.service"])
	}
	if zones["postgresql.service"] != "host-loopback" {
		t.Errorf("postgres trustZone = %q", zones["postgresql.service"])
	}
	if zones["nginx"] != "container-network" {
		t.Errorf("container service trustZone = %q", zones["nginx"])
	}
	if groups["nginx"] != "notprem" {
		t.Errorf("container service group = %q", groups["nginx"])
	}

	// x-trust-boundary must stay unset: it means something else.
	if bytes.Contains(buf.Bytes(), []byte("x-trust-boundary")) {
		t.Error("x-trust-boundary was set; it is a claim about consumer relationships, not bind addresses")
	}

	props := map[string]string{}
	for _, s := range doc.Services {
		if s.Name != "nginx" {
			continue
		}
		for _, p := range s.Properties {
			props[p.Name] = p.Value
		}
	}
	if props["swinv:service:processes"] != "9" {
		t.Errorf("processes property = %q", props["swinv:service:processes"])
	}
	if props["swinv:service:published_as"] != "0.0.0.0:80/tcp" {
		t.Errorf("published_as property = %q", props["swinv:service:published_as"])
	}
}
