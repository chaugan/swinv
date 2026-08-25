package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

func linkReport() *model.Report {
	r := serviceReport()
	r.NDJSONInclude = []string{model.RecordLink}
	r.Services = []model.Service{{
		Endpoints:  []string{"0.0.0.0:22/tcp"},
		Executable: "/usr/sbin/sshd",
		Components: []string{"pkg:deb/ubuntu/openssh-server@10.2p1"},
		Confidence: model.ConfidenceHigh,
		Links: []model.Link{
			{Soname: "libcrypto.so.3", Path: "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
				PURL: "pkg:deb/ubuntu/libssl3t64@3.5.5", NSymbols: 120,
				Symbols: []string{"RSA_set0_key@OPENSSL_3.0.0", "SSL_read@OPENSSL_3.0.0"}},
			{Soname: "libweird.so.9", Path: "/opt/vendor/libweird.so.9"},
			{Soname: "libz.so.1", Path: "/usr/lib/libz.so.1.3.1",
				PURL: "pkg:deb/ubuntu/zlib1g@1.3", Transitive: true},
		},
	}}
	r.Links = []model.BinaryLinks{{
		Executable: "/usr/bin/curl",
		PURL:       "pkg:deb/ubuntu/curl@8.5",
		Links:      []model.Link{{Soname: "libcurl.so.4", Path: "/usr/lib/libcurl.so.4.8.0", PURL: "pkg:deb/ubuntu/libcurl4t64@8.5"}},
	}}
	return r
}

// One record per (executable, library), so the CVE consumer joins on the
// library's package without unpacking anything.
func TestNDJSONLinkRecords(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, linkReport()); err != nil {
		t.Fatal(err)
	}
	rows := recordsOfType(t, buf.Bytes(), "link")
	if len(rows) != 4 {
		t.Fatalf("got %d link records, want 4", len(rows))
	}

	byLib := map[string]map[string]any{}
	for _, r := range rows {
		byLib[r["soname"].(string)] = r
	}

	crypto := byLib["libcrypto.so.3"]
	if crypto["purl"] != "pkg:deb/ubuntu/libssl3t64@3.5.5" {
		t.Errorf("purl = %v", crypto["purl"])
	}
	if crypto["executable_purl"] != "pkg:deb/ubuntu/openssh-server@10.2p1" {
		t.Errorf("executable_purl = %v", crypto["executable_purl"])
	}
	if crypto["listening"] != true {
		t.Error("a listening executable's link is not marked listening")
	}
	// Symbols flattened for the streaming consumer, never as a bare array
	// only.
	if crypto["symbols_text"] != "RSA_set0_key@OPENSSL_3.0.0;SSL_read@OPENSSL_3.0.0" {
		t.Errorf("symbols_text = %v", crypto["symbols_text"])
	}

	// A library nothing owns keeps its record with no purl: for a CVE
	// consumer the unowned copy is the more interesting case, not the less.
	weird := byLib["libweird.so.9"]
	if _, present := weird["purl"]; present {
		t.Errorf("an unowned library carries a purl: %v", weird["purl"])
	}

	if byLib["libz.so.1"]["transitive"] != true {
		t.Error("a transitive link is not marked")
	}

	// The walked-binary table arrives too, unmarked as listening.
	curl := byLib["libcurl.so.4"]
	if curl["listening"] == true {
		t.Error("a walked binary was marked as listening")
	}

	if strings.Contains(buf.String(), ":null") {
		t.Error("a link record emitted a JSON null")
	}
}

// The JSON document carries links on the service, where the exposure question
// is asked.
func TestJSONServiceLinks(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, linkReport()); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services []struct {
			Links []model.Link `json:"links"`
		} `json:"services"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Services[0].Links) != 3 {
		t.Errorf("links = %+v", doc.Services[0].Links)
	}
}

// CycloneDX: the service's dependency edge reaches the packages behind its
// libraries, so a graph walk from the service reaches libssl with no
// swinv-specific knowledge.
func TestCycloneDXServiceLinkEdges(t *testing.T) {
	r := linkReport()
	r.Components = append(r.Components, model.Component{
		Name: "libssl3t64", Version: "3.5.5", Type: "deb", PURL: "pkg:deb/ubuntu/libssl3t64@3.5.5",
	})
	var buf bytes.Buffer
	if err := WriteCycloneDX(&buf, r); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, d := range doc.Dependencies {
		for _, on := range d.DependsOn {
			if on == "pkg:deb/ubuntu/libssl3t64@3.5.5" {
				return
			}
		}
	}
	t.Error("no dependency edge reaches the linked library's package")
}

// Links derive from installed software, which is what the heartbeat digest
// tracks. An unchanged scan therefore emits none: at --elf-scope all they are
// 36,000 rows, and repeating them hourly would undo the heartbeat entirely.
// Exposure and container records still flow, because sockets move while
// software stands still.
func TestNDJSONLinksSuppressedOnUnchangedScan(t *testing.T) {
	r := linkReport()
	r.NDJSONInclude = []string{model.RecordLink, model.RecordExposure}
	r.Exposure = []model.Exposure{{Address: "0.0.0.0", Port: 22, Protocol: "tcp",
		Family: "ipv4", BindScope: model.BindWildcard, Confidence: model.ConfidenceHigh}}
	r.Scan.InventoryDigest = "sha256:abc"
	r.Scan.InventoryUnchanged = true

	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if n := len(recordsOfType(t, buf.Bytes(), "link")); n != 0 {
		t.Errorf("an unchanged scan emitted %d link records", n)
	}
	if n := len(recordsOfType(t, buf.Bytes(), "exposure")); n != 1 {
		t.Errorf("exposure records were suppressed too: %d", n)
	}
}
