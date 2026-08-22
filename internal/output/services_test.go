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

func serviceReport() *model.Report {
	return &model.Report{
		SchemaVersion: model.SchemaVersion,
		Host:          model.Host{Hostname: "web01", MachineID: "abc", OSID: "ubuntu", OSVersionID: "26.04", Architecture: "amd64"},
		Components: []model.Component{
			{Name: "openssh-server", Version: "10.2p1", Type: "deb", PURL: "pkg:deb/ubuntu/openssh-server@10.2p1"},
			{Name: "Some Vendor App", Version: "3.1", Type: "windows"},
		},
		Services: []model.Service{
			{
				Endpoints:  []string{"0.0.0.0:22/tcp"},
				PID:        811,
				Executable: "/usr/sbin/sshd",
				Command:    "sshd: /usr/sbin/sshd -D",
				Unit:       "ssh.service",
				User:       "0",
				Components: []string{"pkg:deb/ubuntu/openssh-server@10.2p1"},
				Confidence: model.ConfidenceHigh,
				Evidence:   []string{"socket 0.0.0.0:22/tcp held by pid 811", "owned by openssh-server"},
			},
			{
				Endpoints:  []string{"127.0.0.1:9000/tcp"},
				PID:        4102,
				Executable: "/opt/vendor/appserver",
				Confidence: model.ConfidenceMedium,
				Evidence:   []string{"no installed package owns this executable"},
			},
			{
				Confidence: model.ConfidenceLow,
				Evidence:   []string{"38 listening socket(s) could not be attributed to a process"},
			},
		},
	}
}

func TestServicesCSVShape(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteServicesCSV(&buf, serviceReport()); err != nil {
		t.Fatalf("WriteServicesCSV: %v", err)
	}

	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want header + 3", len(rows))
	}
	if !reflect.DeepEqual(rows[0], serviceCSVColumns) {
		t.Errorf("header = %v", rows[0])
	}
	for i, row := range rows {
		if len(row) != len(serviceCSVColumns) {
			t.Errorf("row %d has %d fields, want %d", i, len(row), len(serviceCSVColumns))
		}
	}

	// Host identity repeats on every row, which is what lets services files
	// from many machines be concatenated into one table.
	for _, row := range rows[1:] {
		if row[0] != "web01" {
			t.Errorf("hostname = %q on a data row", row[0])
		}
	}

	byConfidence := map[string][]string{}
	for _, row := range rows[1:] {
		byConfidence[row[15]] = row
	}
	if got := byConfidence["high"][14]; got != "pkg:deb/ubuntu/openssh-server@10.2p1" {
		t.Errorf("components = %q", got)
	}
	if got := byConfidence["medium"][14]; got != "" {
		t.Errorf("unowned service claims components %q", got)
	}
	// The aggregate row has no pid; an empty cell, not a literal 0, since 0 is
	// a real pid on some systems and would read as a claim.
	if got := byConfidence["low"][7]; got != "" {
		t.Errorf("pid = %q on the aggregate row, want empty", got)
	}
}

// A header with no rows is the correct empty document: it says the scan looked
// and found nothing, which a zero-byte file does not.
func TestServicesCSVAlwaysWritesTheHeader(t *testing.T) {
	var buf bytes.Buffer
	r := serviceReport()
	r.Services = nil
	if err := WriteServicesCSV(&buf, r); err != nil {
		t.Fatalf("WriteServicesCSV: %v", err)
	}
	if got := strings.Count(buf.String(), "\n"); got != 1 {
		t.Errorf("got %d lines, want just the header", got)
	}
}

// The services CSV enumerates its columns by hand, which is exactly how the
// component NDJSON silently lost two fields. Assert the shape instead.
func TestServicesCSVCarriesEveryServiceField(t *testing.T) {
	columns := map[string]bool{}
	for _, c := range serviceCSVColumns {
		columns[c] = true
	}
	// Field name -> column name, where they differ.
	renamed := map[string]string{"PID": "pid", "OSComponent": "os_component"}

	st := reflect.TypeOf(model.Service{})
	for i := 0; i < st.NumField(); i++ {
		name := st.Field(i).Name
		want, ok := renamed[name]
		if !ok {
			want = snake(name)
		}
		if !columns[want] {
			t.Errorf("model.Service.%s has no %q column, so the services CSV silently omits it", name, want)
		}
	}
}

func snake(s string) string {
	var out []rune
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				out = append(out, '_')
			}
			r += 'a' - 'A'
		}
		out = append(out, r)
	}
	return string(out)
}

func TestCycloneDXServices(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCycloneDX(&buf, serviceReport()); err != nil {
		t.Fatalf("WriteCycloneDX: %v", err)
	}

	var doc struct {
		Services []struct {
			BOMRef     string   `json:"bom-ref"`
			Name       string   `json:"name"`
			Endpoints  []string `json:"endpoints"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"services"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
		Components []struct {
			BOMRef string `json:"bom-ref"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if len(doc.Services) != 3 {
		t.Fatalf("got %d services, want 3", len(doc.Services))
	}
	if doc.Services[0].Name != "ssh.service" {
		t.Errorf("first service name = %q, want the systemd unit", doc.Services[0].Name)
	}
	if len(doc.Services[0].Endpoints) != 1 || doc.Services[0].Endpoints[0] != "0.0.0.0:22/tcp" {
		t.Errorf("endpoints = %v", doc.Services[0].Endpoints)
	}
	// The unattributed aggregate has no unit and no executable, and must still
	// be in the document rather than quietly dropped.
	if doc.Services[2].Name != "unattributed-listeners" {
		t.Errorf("aggregate service name = %q", doc.Services[2].Name)
	}

	var confidence string
	for _, p := range doc.Services[0].Properties {
		if p.Name == "swinv:service:confidence" {
			confidence = p.Value
		}
	}
	if confidence != "high" {
		t.Errorf("confidence property = %q", confidence)
	}

	// The dependency edge is the point: it must reference a bom-ref that
	// actually exists in the document, not a plausible-looking string.
	if len(doc.Dependencies) != 1 {
		t.Fatalf("got %d dependencies, want 1", len(doc.Dependencies))
	}
	if doc.Dependencies[0].Ref != doc.Services[0].BOMRef {
		t.Errorf("dependency ref = %q, want %q", doc.Dependencies[0].Ref, doc.Services[0].BOMRef)
	}
	refs := map[string]bool{}
	for _, c := range doc.Components {
		refs[c.BOMRef] = true
	}
	for _, on := range doc.Dependencies[0].DependsOn {
		if !refs[on] {
			t.Errorf("dependsOn %q matches no component bom-ref in the document", on)
		}
	}
}

// A service whose software has no PURL -- a Windows registry entry -- must
// still resolve to that component's bom-ref, which is the one case where the
// two spellings could drift apart.
func TestCycloneDXServiceDependencyWithoutAPURL(t *testing.T) {
	r := serviceReport()
	r.Services = []model.Service{{
		Endpoints:  []string{"0.0.0.0:8080/tcp"},
		Executable: `C:\Program Files\Vendor\app.exe`,
		Components: []string{"Some Vendor App@3.1"},
		Confidence: model.ConfidenceHigh,
	}}

	var buf bytes.Buffer
	if err := WriteCycloneDX(&buf, r); err != nil {
		t.Fatalf("WriteCycloneDX: %v", err)
	}
	var doc struct {
		Dependencies []struct {
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Dependencies) != 1 || len(doc.Dependencies[0].DependsOn) != 1 ||
		doc.Dependencies[0].DependsOn[0] != "windows:Some Vendor App@3.1" {
		t.Errorf("dependsOn = %+v", doc.Dependencies)
	}
}

// The service name falls back to the executable's basename, and must do so for
// a Windows path too -- path.Base alone would return the whole string.
func TestCycloneDXServiceNameFromWindowsPath(t *testing.T) {
	got := serviceName(model.Service{Executable: `C:\Program Files\Vendor\app.exe`})
	if got != "app.exe" {
		t.Errorf("serviceName = %q, want app.exe", got)
	}
}
