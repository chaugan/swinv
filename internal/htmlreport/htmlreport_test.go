package htmlreport

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/chaugan/swinv/internal/model"
)

func sampleReport() *model.Report {
	return &model.Report{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.Tool{Name: "swinv", Version: "v9.9.9"},
		Host:          model.Host{Hostname: "testhost", OSID: "ubuntu", OSVersionID: "26.04", KernelRelease: "7.0.0"},
		Scan: model.ScanMeta{
			StartedAt: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC),
			Profile: &model.ScanProfile{
				Hash:          true,
				ELFScope:      "all",
				ConfigScope:   "all",
				NDJSONInclude: []string{"component", "exposure", "containers"},
				Services:      true,
				Containers:    true,
				Root:          "/",
			},
			Sources: map[string]model.SourceStatus{
				"dpkg": {Status: model.SourceOK, Components: 2},
				"apk":  {Status: model.SourceSkipped, Reason: "not present"},
			},
		},
		Components: []model.Component{
			{Name: "openssl", Version: "3.0", Type: "deb", Root: "/", SourceKey: "dpkg", PURL: "pkg:deb/openssl@3.0"},
			{Name: "bash", Version: "5.2", Type: "deb", Root: "/", SourceKey: "dpkg", PURL: "pkg:deb/bash@5.2"},
		},
		Links: []model.BinaryLinks{{
			Executable: "/usr/sbin/nginx",
			Links: []model.Link{
				{Soname: "libc.so.6", Path: "/lib/libc.so.6", OSComponent: true},
				{Soname: "libfoo.so.1", Path: "/opt/libfoo.so.1"}, // unowned
			},
		}},
		ConfigSurface: []model.ConfigEntry{
			{Kind: "cron", Name: "backup", Path: "/etc/cron.d/backup", User: "root", Attack: "T1053", Executable: "/opt/b.sh", WorldWritable: true, Evidence: []string{"a", "b"}},
		},
		Exposure: []model.Exposure{
			{Address: "0.0.0.0", Port: 22, Protocol: "tcp", BindScope: model.BindWildcard, Executable: "/usr/sbin/sshd", Components: []string{"pkg:deb/openssh"}, Confidence: model.ConfidenceHigh},
			{Address: "127.0.0.1", Port: 5432, Protocol: "tcp", BindScope: model.BindLoopback, Executable: "/usr/bin/postgres"},
		},
		Containers: []model.Container{
			{ID: "abc123def456ghi", Name: "web", State: "running", OSID: "alpine", OSVersionID: "3.20", Image: &model.Image{Ref: "nginx:latest"}},
		},
	}
}

func TestWriteHTMLProducesSelfContainedPage(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()

	for _, must := range []string{
		"<!doctype html>",
		`id="swinv-data"`,
		"testhost",
		`id="ch-type"`,
		`id="tb-comp"`,
		`id="tb-exp"`,
		`id="tb-cfg"`,
		`id="tb-unl"`,
		`id="tb-ct"`,
	} {
		if !strings.Contains(out, must) {
			t.Errorf("output missing %q", must)
		}
	}

	// Offline promise: no external references.
	for _, forbidden := range []string{"http://", "https://fonts", "src=\"//", "cdn."} {
		if strings.Contains(out, forbidden) {
			t.Errorf("page reaches out to %q; it must be self-contained", forbidden)
		}
	}
}

func TestWriteHTMLNil(t *testing.T) {
	if err := WriteHTML(&bytes.Buffer{}, nil); err == nil {
		t.Fatal("expected error on nil report")
	}
}

func TestCmdLineReconstruction(t *testing.T) {
	cases := []struct {
		name string
		p    *model.ScanProfile
		want string
	}{
		{"nil", nil, "swinv"},
		{"defaults", &model.ScanProfile{ELFScope: "listening", ConfigScope: "standard", Services: true, Containers: true, Root: "/"}, "swinv"},
		{"rich", &model.ScanProfile{Hash: true, ELFScope: "all", ConfigScope: "all", NDJSONInclude: []string{"component", "exposure", "containers"}, Services: true, Containers: true, Root: "/"},
			"swinv --hash --elf-scope all --config-scope all --ndjson-include exposure,containers"},
		{"disabled", &model.ScanProfile{ELFScope: "off", ConfigScope: "off", Services: false, Containers: false, Root: "/srv"},
			"swinv --root /srv --elf-scope off --config-scope off --no-services --no-containers"},
		{"quoted root", &model.ScanProfile{ELFScope: "listening", ConfigScope: "standard", Services: true, Containers: true, Root: "/opt/my data"},
			"swinv --root '/opt/my data'"},
		// When the invocation was recorded, it is shown verbatim -- including
		// flags the scope fields cannot recover, a Windows path unquoted, and a
		// path with a space quoted.
		{"recorded args", &model.ScanProfile{Args: []string{"--out", `C:\ProgramData\swinv`, "--heartbeat", "--offline", "--config-scope", "all"}},
			`swinv --out C:\ProgramData\swinv --heartbeat --offline --config-scope all`},
		{"recorded args with a space", &model.ScanProfile{Args: []string{"--out", "/var/my reports", "--hash"}},
			"swinv --out '/var/my reports' --hash"},
		{"all-interfaces", &model.ScanProfile{AllInterfaces: true, ELFScope: "listening", ConfigScope: "standard", Services: true, Containers: true, Root: "/"},
			"swinv --all-interfaces"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cmdLine(c.p, nil); got != c.want {
				t.Errorf("cmdLine = %q, want %q", got, c.want)
			}
		})
	}
}

func TestAggregateOwnershipSplit(t *testing.T) {
	d := aggregate(sampleReport())
	if d.Insights.UnownedLinkCount != 1 {
		t.Errorf("unowned links = %d, want 1", d.Insights.UnownedLinkCount)
	}
	if d.Insights.BeyondLoopback != 1 {
		t.Errorf("beyond loopback = %d, want 1", d.Insights.BeyondLoopback)
	}
	if len(d.Insights.UnownedExecConfigs) != 1 {
		t.Errorf("unowned exec configs = %d, want 1", len(d.Insights.UnownedExecConfigs))
	}
	if got := d.Meta.Counts["component"]; got != 2 {
		t.Errorf("component count = %d, want 2", got)
	}
}

// TestWriteHTMLEscapesHostileData feeds attacker-controllable strings (a
// component name, type, and library path an unprivileged user could plant on a
// scanned host) and checks none can break out of the JSON data island or an
// HTML attribute. The chart click-filter labels (type, source, attack) are the
// values that used to be injected into an onclick attribute; they must now
// reach the DOM only as escaped data.
// TestHTMLInterfacesBlockStatesTheFlagBothWays is the HTML side of
// --all-interfaces: when the scan collected the table, the page carries it
// with the rows and says which flag produced them; when it did not, the page
// must say "not collected" rather than render an empty table that reads as a
// machine with no network.
func TestHTMLInterfacesBlockStatesTheFlagBothWays(t *testing.T) {
	collected := sampleReport()
	collected.Scan.Profile.AllInterfaces = true
	collected.Host.Interfaces = []model.NetInterface{
		{Name: "lo", Type: "loopback", State: "up", MTU: 65536, IPs: []string{"127.0.0.1/8", "::1/128"}},
		{Name: "eth0", Type: "ethernet", State: "up", MTU: 1500, MAC: "52:54:00:ab:cd:ef", IPs: []string{"10.0.0.7/24", "fe80::5054:ff:feab:cdef/64"}},
		{Name: "mgmt0", Type: "other", State: "down", IPs: []string{"192.168.100.5/24"}},
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, collected); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	page := buf.String()
	for _, want := range []string{
		"Network interfaces", "tb-iface",
		"eth0", "loopback", "52:54:00:ab:cd:ef",
		// CIDR form survives to the page, and the down interface with an
		// address nobody can reach still shows: down is a fact, not a filter.
		"10.0.0.7/24", "mgmt0",
		// The flag is declared in the profile chips and the block provenance.
		"all-interfaces",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("collected page is missing %q", want)
		}
	}

	// Off: the block says so, no table is created (an empty one would read as
	// a quiet machine), and the usable identity still stands on its own.
	off := sampleReport()
	buf.Reset()
	if err := WriteHTML(&buf, off); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	page = buf.String()
	if !strings.Contains(page, "Not collected") || !strings.Contains(page, "--all-interfaces off") {
		t.Error("the off state does not say the interfaces were not collected")
	}
	if strings.Contains(page, `id="tb-iface"`) {
		t.Error("an interface table was rendered for a scan that did not collect them")
	}
	if strings.Contains(page, ">eth0<") {
		t.Error("interface rows leaked into a page whose scan did not collect them")
	}
}

func TestWriteHTMLEscapesHostileData(t *testing.T) {
	r := sampleReport()
	r.Components = append(r.Components, model.Component{
		Name:      `pwn</script><img src=x onerror=alert(1)>`,
		Version:   `1.0"><svg onload=alert(2)>`,
		Type:      `evil"onx`,
		SourceKey: `src"><b`,
		Root:      "/",
	})
	r.Links = append(r.Links, model.BinaryLinks{
		Executable: `/tmp/evil</script>`,
		Links:      []model.Link{{Soname: `lib"><img>.so`, Path: `/tmp/x</script>`}},
	})

	var buf bytes.Buffer
	if err := WriteHTML(&buf, r); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()

	// The data island cannot be closed early: json.Marshal escapes '<' and
	// '>', so no payload's "</script>" or "<img" survives as literal markup.
	for _, breakout := range []string{"</script><img", "<img src=x onerror", "<svg onload", `"><b`, `"><img>`} {
		if strings.Contains(out, breakout) {
			t.Errorf("hostile payload %q appears unescaped in the output", breakout)
		}
	}
	// And the escaped form is what actually rides in the blob: json.Marshal
	// renders '<' and '>' as < / >, which the browser reads as data.
	if !strings.Contains(out, `\u003c/script\u003e\u003cimg`) {
		t.Error("expected the component name to survive as escaped \\u003c form in the data island")
	}
}
