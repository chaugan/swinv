package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

func streamReport() *model.Report {
	r := serviceReport()
	r.NDJSONInclude = []string{"container", "exposure"}
	r.Containers = []model.Container{{
		ID:                "f6e3203743df0000000000000000000000000000000000000000000000000000",
		Name:              "app-web-1",
		Runtime:           "docker",
		State:             "exited",
		Image:             &model.Image{Ref: "nginx:1.25", ManifestDigest: "sha256:abc", PURL: "pkg:oci/nginx@sha256%3Aabc"},
		OSID:              "debian",
		OSVersionID:       "12",
		DeclaredEndpoints: []string{"80/tcp"},
		Services: []model.Service{{
			Endpoints: []string{"0.0.0.0:80/tcp", "[::]:80/tcp6"},
		}},
	}}
	r.Exposure = []model.Exposure{
		{
			Address: "0.0.0.0", Port: 22, Protocol: "tcp", Family: "ipv4",
			BindScope: model.BindWildcard, Executable: "/usr/sbin/sshd",
			Unit: "ssh.service", User: "0", Processes: 2,
			Components: []string{"pkg:deb/ubuntu/openssh-server@10.2p1", "pkg:deb/ubuntu/openssh-sftp-server@10.2p1"},
			Confidence: model.ConfidenceHigh,
		},
		{
			// A port answering with no package behind it is a gap in what can
			// be seen, not a port that is safe.
			Address: "0.0.0.0", Port: 9000, Protocol: "tcp", Family: "ipv4",
			BindScope: model.BindWildcard, Executable: "/opt/vendor/app",
			Confidence: model.ConfidenceMedium,
		},
		{
			Address: "0.0.0.0", Port: 80, Protocol: "tcp", Family: "ipv4",
			BindScope: model.BindWildcard, Executable: "/usr/bin/docker-proxy",
			Backend: &model.Backend{
				Container:  "f6e3203743df0000000000000000000000000000000000000000000000000000",
				Executable: "/usr/sbin/nginx",
			},
			Components: []string{"pkg:apk/alpine/nginx@1.27.5-r1"},
			Confidence: model.ConfidenceHigh,
		},
	}
	return r
}

func recordsOfType(t *testing.T, raw []byte, want string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line is not valid JSON: %v\n%s", err, line)
		}
		if m["record_type"] == want {
			out = append(out, m)
		}
	}
	return out
}

// One record per (port, package), so a finding joins on the package alone
// without the consumer unpacking an array.
func TestNDJSONExposureRecordsAreDenormalised(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, streamReport()); err != nil {
		t.Fatalf("WriteNDJSON: %v", err)
	}
	rows := recordsOfType(t, buf.Bytes(), "exposure")

	// 2 packages on :22, 1 unattributed on :9000, 1 on :80.
	if len(rows) != 4 {
		t.Fatalf("got %d exposure records, want 4", len(rows))
	}

	var ssh int
	for _, r := range rows {
		if r["port"] == float64(22) {
			ssh++
			if r["purl"] == nil || r["purl"] == "" {
				t.Error("an attributed port produced a record with no purl")
			}
		}
	}
	if ssh != 2 {
		t.Errorf("port 22 produced %d records, want one per package", ssh)
	}
}

// A port answering with no package behind it must survive. Dropping it here
// would hide it completely, and it is a gap in what can be seen rather than a
// port that is safe.
func TestNDJSONExposureKeepsUnattributedPorts(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, streamReport()); err != nil {
		t.Fatal(err)
	}
	for _, r := range recordsOfType(t, buf.Bytes(), "exposure") {
		if r["port"] != float64(9000) {
			continue
		}
		if _, present := r["purl"]; present {
			t.Errorf("an unattributed port carries a purl: %v", r["purl"])
		}
		if r["executable"] != "/opt/vendor/app" {
			t.Errorf("executable = %v", r["executable"])
		}
		return
	}
	t.Fatal("the unattributed port produced no record at all")
}

// A published port names the container behind it, not the forwarder.
func TestNDJSONExposureFollowsThePublishedPort(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, streamReport()); err != nil {
		t.Fatal(err)
	}
	for _, r := range recordsOfType(t, buf.Bytes(), "exposure") {
		if r["port"] != float64(80) {
			continue
		}
		if r["container_name"] != "app-web-1" {
			t.Errorf("container_name = %v", r["container_name"])
		}
		if r["executable"] != "/usr/sbin/nginx" {
			t.Errorf("executable = %v, want the process inside the container", r["executable"])
		}
		return
	}
	t.Fatal("no record for the published port")
}

// Stopped containers are one `docker start` from running; their
// vulnerabilities are latent, not absent.
func TestNDJSONContainerRecords(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, streamReport()); err != nil {
		t.Fatal(err)
	}
	rows := recordsOfType(t, buf.Bytes(), "container")
	if len(rows) != 1 {
		t.Fatalf("got %d container records", len(rows))
	}
	c := rows[0]
	if c["state"] != "exited" {
		t.Errorf("state = %v; a stopped container must still be reported", c["state"])
	}
	if c["os_id"] != "debian" || c["os_version_id"] != "12" {
		t.Errorf("container OS = %v %v, which is what its packages must be matched against",
			c["os_id"], c["os_version_id"])
	}
	if c["image_digest"] != "sha256:abc" {
		t.Errorf("image_digest = %v", c["image_digest"])
	}

	// Splunk renames an array field with a "{}" suffix, so a search asking for
	// "endpoints" silently gets nothing. The flattened forms remove that edge.
	if c["endpoints_text"] != "0.0.0.0:80/tcp;[::]:80/tcp6" {
		t.Errorf("endpoints_text = %v", c["endpoints_text"])
	}
	if c["n_endpoints"] != float64(2) {
		t.Errorf("n_endpoints = %v", c["n_endpoints"])
	}
	if c["declared_endpoints_text"] != "80/tcp" || c["n_declared_endpoints"] != float64(1) {
		t.Errorf("declared endpoints = %v / %v", c["declared_endpoints_text"], c["n_declared_endpoints"])
	}
}

// Splunk indexes a JSON null as the four-character string "null", so an absent
// unit becomes a systemd unit named "null" on every listener.
func TestNDJSONRecordsNeverEmitNull(t *testing.T) {
	r := streamReport()
	r.Host.MachineID = ""
	r.Containers[0].Runtime = ""
	r.Containers[0].Image = nil

	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), ":null") {
		t.Error("a record emitted a JSON null; Splunk indexes that as the string \"null\"")
	}
}

// Off by default: a consumer reading every line as a component predates all of
// this, and an unrecognised record would arrive as a component with no name.
func TestNDJSONExtraRecordsAreOptIn(t *testing.T) {
	r := streamReport()
	r.NDJSONInclude = nil

	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "record_type") {
		t.Error("extra records were emitted without --ndjson-include")
	}
}

// The heartbeat suppresses the *components*, which are the volume. What is
// listening can change while the installed software does not -- a port opened,
// a container started -- so suppressing those too would make the heartbeat
// hide the fastest-moving facts in the report.
func TestNDJSONHeartbeatKeepsExposureAndContainers(t *testing.T) {
	r := streamReport()
	r.Scan.InventoryDigest = "sha256:abc"
	r.Scan.InventoryUnchanged = true

	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if n := len(recordsOfType(t, buf.Bytes(), "exposure")); n != 4 {
		t.Errorf("got %d exposure records on an unchanged scan, want 4", n)
	}
	if n := len(recordsOfType(t, buf.Bytes(), "container")); n != 1 {
		t.Errorf("got %d container records on an unchanged scan, want 1", n)
	}
	// And still no components, which is the whole point of the heartbeat.
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m["record_type"]; !ok {
			t.Errorf("a component record survived an unchanged scan: %s", line)
		}
	}
}
