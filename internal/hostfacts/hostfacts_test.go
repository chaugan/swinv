package hostfacts

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// writeFixture materialises a map of slash-separated relative paths to file
// contents inside a fresh temporary directory and returns its root.
func writeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "empty input",
			input: "",
			want:  map[string]string{},
		},
		{
			name:  "unquoted value",
			input: "ID=ubuntu\n",
			want:  map[string]string{"ID": "ubuntu"},
		},
		{
			name:  "double quoted value",
			input: "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n",
			want:  map[string]string{"PRETTY_NAME": "Ubuntu 24.04.1 LTS"},
		},
		{
			name:  "single quoted value keeps backslashes literally",
			input: "NAME='Debian GNU/Linux \\n'\n",
			want:  map[string]string{"NAME": "Debian GNU/Linux \\n"},
		},
		{
			name:  "escaped characters inside double quotes",
			input: "A=\"say \\\"hi\\\"\"\nB=\"back\\\\slash\"\nC=\"cost \\$5\"\nD=\"tick \\`x\\`\"\n",
			want: map[string]string{
				"A": `say "hi"`,
				"B": `back\slash`,
				"C": "cost $5",
				"D": "tick `x`",
			},
		},
		{
			name:  "escape sequences n and t expand",
			input: "MSG=\"one\\ntwo\\tthree\"\n",
			want:  map[string]string{"MSG": "one\ntwo\tthree"},
		},
		{
			name:  "unknown escape drops the backslash",
			input: "V=\"a\\db\"\n",
			want:  map[string]string{"V": "adb"},
		},
		{
			name:  "trailing lone backslash is dropped",
			input: "V=\"abc\\\"\n",
			// The final backslash escapes the closing quote, so the value is
			// unbalanced and is handed back verbatim.
			want: map[string]string{"V": `"abc\"`},
		},
		{
			name:  "blank lines and whitespace only lines are ignored",
			input: "\n   \n\t\nID=fedora\n\n",
			want:  map[string]string{"ID": "fedora"},
		},
		{
			name:  "comments are ignored",
			input: "# a comment\nID=alpine\n   # indented comment\n#ID=nope\n",
			want:  map[string]string{"ID": "alpine"},
		},
		{
			name:  "malformed line without equals is skipped",
			input: "this line has no equals sign\nID=rhel\njust-a-key\n",
			want:  map[string]string{"ID": "rhel"},
		},
		{
			name:  "empty key is skipped",
			input: "=orphan\nID=arch\n",
			want:  map[string]string{"ID": "arch"},
		},
		{
			name:  "CRLF line endings",
			input: "ID=sles\r\nVERSION_ID=\"15.6\"\r\n\r\n# comment\r\n",
			want:  map[string]string{"ID": "sles", "VERSION_ID": "15.6"},
		},
		{
			name:  "surrounding whitespace is trimmed",
			input: "  ID  =  centos  \n",
			want:  map[string]string{"ID": "centos"},
		},
		{
			name:  "empty value",
			input: "ID=\nVERSION_ID=\"\"\nX=''\n",
			want:  map[string]string{"ID": "", "VERSION_ID": "", "X": ""},
		},
		{
			name:  "value containing equals signs",
			input: "CPE_NAME=\"cpe:/o:fedoraproject:fedora:40\"\nX=a=b=c\n",
			want:  map[string]string{"CPE_NAME": "cpe:/o:fedoraproject:fedora:40", "X": "a=b=c"},
		},
		{
			name:  "unbalanced quote is kept verbatim",
			input: "A=\"open\nB='half\n",
			want:  map[string]string{"A": `"open`, "B": `'half`},
		},
		{
			name:  "mismatched quote pair is kept verbatim",
			input: "A=\"mixed'\n",
			want:  map[string]string{"A": `"mixed'`},
		},
		{
			name:  "later assignment wins",
			input: "ID=first\nID=second\n",
			want:  map[string]string{"ID": "second"},
		},
		{
			name:  "no trailing newline",
			input: "ID=void",
			want:  map[string]string{"ID": "void"},
		},
		{
			name: "realistic ubuntu os-release",
			input: `PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
`,
			want: map[string]string{
				"PRETTY_NAME":      "Ubuntu 24.04.1 LTS",
				"NAME":             "Ubuntu",
				"VERSION_ID":       "24.04",
				"VERSION":          "24.04.1 LTS (Noble Numbat)",
				"VERSION_CODENAME": "noble",
				"ID":               "ubuntu",
				"ID_LIKE":          "debian",
				"HOME_URL":         "https://www.ubuntu.com/",
				"UBUNTU_CODENAME":  "noble",
				"LOGO":             "ubuntu-logo",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseOSRelease(strings.NewReader(tc.input))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseOSRelease(%q)\n got: %#v\nwant: %#v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseOSReleaseNilReader(t *testing.T) {
	got := ParseOSRelease(nil)
	if got == nil || len(got) != 0 {
		t.Fatalf("ParseOSRelease(nil) = %#v, want empty non-nil map", got)
	}
}

func TestCollectFullFixtureTree(t *testing.T) {
	root := writeFixture(t, map[string]string{
		"etc/hostname":                   "fixture-host\n",
		"etc/machine-id":                 "0123456789abcdef0123456789abcdef\n",
		"proc/sys/kernel/random/boot_id": "8f8e1a3c-1111-2222-3333-444455556666\n",
		"proc/sys/kernel/osrelease":      "6.8.0-45-generic\n",
		"etc/os-release": "ID=ubuntu\nVERSION_ID=\"24.04\"\n" +
			"PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n",
		"sys/class/dmi/id/sys_vendor":     "QEMU\n",
		"sys/class/dmi/id/product_name":   "Standard PC (i440FX + PIIX, 1996)\n",
		"sys/class/dmi/id/product_serial": "SN-12345\n",
		"sys/class/dmi/id/product_uuid":   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n",
	})

	h := Collect(context.Background(), root)

	checks := []struct{ field, got, want string }{
		{"Hostname", h.Hostname, "fixture-host"},
		{"MachineID", h.MachineID, "0123456789abcdef0123456789abcdef"},
		{"BootID", h.BootID, "8f8e1a3c-1111-2222-3333-444455556666"},
		{"KernelRelease", h.KernelRelease, "6.8.0-45-generic"},
		{"OSID", h.OSID, "ubuntu"},
		{"OSVersionID", h.OSVersionID, "24.04"},
		{"OSPrettyName", h.OSPrettyName, "Ubuntu 24.04.1 LTS"},
		{"SystemVendor", h.SystemVendor, "QEMU"},
		{"ProductName", h.ProductName, "Standard PC (i440FX + PIIX, 1996)"},
		{"ProductSerial", h.ProductSerial, "SN-12345"},
		{"ProductUUID", h.ProductUUID, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		{"Virtualization", h.Virtualization, "qemu"},
		{"Architecture", h.Architecture, runtime.GOARCH},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
		}
	}

	// Network facts must be skipped for a fixture tree so tests stay hermetic.
	if h.FQDN != "" || h.IPv4 != nil || h.IPv6 != nil || h.MACs != nil {
		t.Errorf("network facts leaked for fsRoot %q: fqdn=%q ipv4=%v ipv6=%v macs=%v",
			root, h.FQDN, h.IPv4, h.IPv6, h.MACs)
	}
}

func TestCollectMissingFiles(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
	}{
		{name: "completely empty tree", files: map[string]string{}},
		{name: "os-release present but empty", files: map[string]string{"etc/os-release": ""}},
		{name: "machine-id present but blank", files: map[string]string{"etc/machine-id": "\n\n"}},
		{
			name: "sources are directories rather than files",
			files: map[string]string{
				"etc/machine-id/placeholder": "x",
				"etc/os-release/placeholder": "x",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := writeFixture(t, tc.files)
			h := Collect(context.Background(), root)

			if h.MachineID != "" {
				t.Errorf("MachineID = %q, want empty", h.MachineID)
			}
			for _, c := range []struct{ field, got string }{
				{"BootID", h.BootID},
				{"KernelRelease", h.KernelRelease},
				{"OSID", h.OSID},
				{"OSVersionID", h.OSVersionID},
				{"OSPrettyName", h.OSPrettyName},
				{"SystemVendor", h.SystemVendor},
				{"ProductName", h.ProductName},
				{"ProductSerial", h.ProductSerial},
				{"ProductUUID", h.ProductUUID},
				{"Virtualization", h.Virtualization},
				{"FQDN", h.FQDN},
			} {
				if c.got != "" {
					t.Errorf("%s = %q, want empty", c.field, c.got)
				}
			}
			// Architecture is always available; it comes from the build.
			if h.Architecture != runtime.GOARCH {
				t.Errorf("Architecture = %q, want %q", h.Architecture, runtime.GOARCH)
			}
		})
	}
}

func TestCollectMachineIDFallback(t *testing.T) {
	const etcID = "1111111111111111111111111111aaaa"
	const dbusID = "2222222222222222222222222222bbbb"

	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name:  "etc machine-id preferred",
			files: map[string]string{"etc/machine-id": etcID + "\n", "var/lib/dbus/machine-id": dbusID + "\n"},
			want:  etcID,
		},
		{
			name:  "falls back to dbus machine-id when etc is missing",
			files: map[string]string{"var/lib/dbus/machine-id": dbusID + "\n"},
			want:  dbusID,
		},
		{
			name:  "falls back to dbus machine-id when etc is empty",
			files: map[string]string{"etc/machine-id": "\n", "var/lib/dbus/machine-id": dbusID + "\n"},
			want:  dbusID,
		},
		{
			name:  "both missing yields empty",
			files: map[string]string{},
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := writeFixture(t, tc.files)
			if got := Collect(context.Background(), root).MachineID; got != tc.want {
				t.Errorf("MachineID = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCollectOSReleaseFallsBackToUsrLib(t *testing.T) {
	tests := []struct {
		name               string
		files              map[string]string
		wantID, wantPretty string
	}{
		{
			name: "etc wins over usr lib",
			files: map[string]string{
				"etc/os-release":     "ID=debian\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n",
				"usr/lib/os-release": "ID=ignored\nPRETTY_NAME=\"Ignored\"\n",
			},
			wantID: "debian", wantPretty: "Debian GNU/Linux 12",
		},
		{
			name: "usr lib used when etc is absent",
			files: map[string]string{
				"usr/lib/os-release": "ID=alpine\nPRETTY_NAME=\"Alpine Linux v3.20\"\n",
			},
			wantID: "alpine", wantPretty: "Alpine Linux v3.20",
		},
		{
			name: "usr lib used when etc parses to nothing",
			files: map[string]string{
				"etc/os-release":     "# only comments\n\n",
				"usr/lib/os-release": "ID=arch\nPRETTY_NAME=\"Arch Linux\"\n",
			},
			wantID: "arch", wantPretty: "Arch Linux",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := Collect(context.Background(), writeFixture(t, tc.files))
			if h.OSID != tc.wantID {
				t.Errorf("OSID = %q, want %q", h.OSID, tc.wantID)
			}
			if h.OSPrettyName != tc.wantPretty {
				t.Errorf("OSPrettyName = %q, want %q", h.OSPrettyName, tc.wantPretty)
			}
		})
	}
}

func TestCollectDMI(t *testing.T) {
	tests := []struct {
		name                             string
		files                            map[string]string
		vendor, product, serial, uuidVal string
	}{
		{
			name: "all four present",
			files: map[string]string{
				"sys/class/dmi/id/sys_vendor":     "Dell Inc.\n",
				"sys/class/dmi/id/product_name":   "PowerEdge R640\n",
				"sys/class/dmi/id/product_serial": "ABC1234\n",
				"sys/class/dmi/id/product_uuid":   "4c4c4544-0041-1234-1234-b9c04f424331\n",
			},
			vendor: "Dell Inc.", product: "PowerEdge R640",
			serial: "ABC1234", uuidVal: "4c4c4544-0041-1234-1234-b9c04f424331",
		},
		{
			name: "root only fields absent for an unprivileged run",
			files: map[string]string{
				"sys/class/dmi/id/sys_vendor":   "LENOVO\n",
				"sys/class/dmi/id/product_name": "20XW00ABMX\n",
			},
			vendor: "LENOVO", product: "20XW00ABMX",
		},
		{
			name: "firmware placeholders are discarded",
			files: map[string]string{
				"sys/class/dmi/id/sys_vendor":     "To be filled by O.E.M.\n",
				"sys/class/dmi/id/product_name":   "Default string\n",
				"sys/class/dmi/id/product_serial": "System Serial Number\n",
				"sys/class/dmi/id/product_uuid":   "00000000-0000-0000-0000-000000000000\n",
			},
		},
		{
			name: "trailing whitespace and stray content trimmed",
			files: map[string]string{
				"sys/class/dmi/id/sys_vendor":   "  Supermicro  \n",
				"sys/class/dmi/id/product_name": "X11DPi-N\nextra\n",
			},
			vendor: "Supermicro", product: "X11DPi-N",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := Collect(context.Background(), writeFixture(t, tc.files))
			for _, c := range []struct{ field, got, want string }{
				{"SystemVendor", h.SystemVendor, tc.vendor},
				{"ProductName", h.ProductName, tc.product},
				{"ProductSerial", h.ProductSerial, tc.serial},
				{"ProductUUID", h.ProductUUID, tc.uuidVal},
			} {
				if c.got != c.want {
					t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
				}
			}
		})
	}
}

// TestCollectUnreadableDMIIsSilent covers the spec requirement that a root-only
// DMI read failing with EACCES leaves the field empty and produces no warning,
// no log line, and no panic.
func TestCollectUnreadableDMIIsSilent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: file modes cannot make a read fail with EACCES")
	}

	root := writeFixture(t, map[string]string{
		"etc/machine-id":                  "3333333333333333333333333333cccc\n",
		"sys/class/dmi/id/sys_vendor":     "HP\n",
		"sys/class/dmi/id/product_serial": "TOP-SECRET\n",
		"sys/class/dmi/id/product_uuid":   "deadbeef-0000-0000-0000-000000000000\n",
	})
	for _, rel := range []string{"sys/class/dmi/id/product_serial", "sys/class/dmi/id/product_uuid"} {
		if err := os.Chmod(filepath.Join(root, filepath.FromSlash(rel)), 0o000); err != nil {
			t.Fatalf("chmod %s: %v", rel, err)
		}
	}

	// Capture anything the package might emit through either logging facility.
	var logged bytes.Buffer
	origLogOut, origLogFlags, origLogPrefix := log.Writer(), log.Flags(), log.Prefix()
	origSlog := slog.Default()
	log.SetOutput(&logged)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() {
		log.SetOutput(origLogOut)
		log.SetFlags(origLogFlags)
		log.SetPrefix(origLogPrefix)
		slog.SetDefault(origSlog)
	})

	h := Collect(context.Background(), root)

	if h.ProductSerial != "" {
		t.Errorf("ProductSerial = %q, want empty for an unreadable file", h.ProductSerial)
	}
	if h.ProductUUID != "" {
		t.Errorf("ProductUUID = %q, want empty for an unreadable file", h.ProductUUID)
	}
	// Readable facts must still be collected.
	if h.SystemVendor != "HP" {
		t.Errorf("SystemVendor = %q, want %q", h.SystemVendor, "HP")
	}
	if h.MachineID != "3333333333333333333333333333cccc" {
		t.Errorf("MachineID = %q, want the fixture value", h.MachineID)
	}
	if logged.Len() != 0 {
		t.Errorf("Collect logged %q, want no output at all", logged.String())
	}
}

// TestCollectUnreadableDirectorySilent exercises the case where the whole DMI
// directory is unreadable, which is what a hardened container looks like.
func TestCollectUnreadableDirectorySilent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: file modes cannot make a read fail with EACCES")
	}
	root := writeFixture(t, map[string]string{
		"sys/class/dmi/id/sys_vendor": "QEMU\n",
	})
	dmiDir := filepath.Join(root, "sys", "class", "dmi", "id")
	if err := os.Chmod(dmiDir, 0o000); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dmiDir, 0o755) })

	h := Collect(context.Background(), root)
	if h.SystemVendor != "" || h.ProductName != "" || h.Virtualization != "" {
		t.Errorf("expected empty DMI facts, got vendor=%q product=%q virt=%q",
			h.SystemVendor, h.ProductName, h.Virtualization)
	}
}

func TestDetectVirtualization(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{name: "bare metal", files: map[string]string{
			"sys/class/dmi/id/sys_vendor":   "Dell Inc.\n",
			"sys/class/dmi/id/product_name": "PowerEdge R640\n",
		}, want: ""},
		{name: "no sources at all", files: map[string]string{}, want: ""},
		{name: "kvm", files: map[string]string{
			"sys/class/dmi/id/product_name": "KVM Virtual Machine\n",
		}, want: "kvm"},
		{name: "qemu via vendor", files: map[string]string{
			"sys/class/dmi/id/sys_vendor":   "QEMU\n",
			"sys/class/dmi/id/product_name": "Standard PC (Q35 + ICH9, 2009)\n",
		}, want: "qemu"},
		{name: "vmware", files: map[string]string{
			"sys/class/dmi/id/product_name": "VMware Virtual Platform\n",
		}, want: "vmware"},
		{name: "virtualbox", files: map[string]string{
			"sys/class/dmi/id/product_name": "VirtualBox\n",
			"sys/class/dmi/id/sys_vendor":   "innotek GmbH\n",
		}, want: "virtualbox"},
		{name: "virtualbox via vendor only", files: map[string]string{
			"sys/class/dmi/id/sys_vendor": "innotek GmbH\n",
		}, want: "virtualbox"},
		{name: "xen hvm via dmi", files: map[string]string{
			"sys/class/dmi/id/product_name": "HVM domU\n",
		}, want: "xen"},
		{name: "xen pv via hypervisor type", files: map[string]string{
			"sys/hypervisor/type": "xen\n",
		}, want: "xen"},
		{name: "hyper-v", files: map[string]string{
			"sys/class/dmi/id/product_name": "Virtual Machine\n",
			"sys/class/dmi/id/sys_vendor":   "Microsoft Corporation\n",
		}, want: "hyperv"},
		{name: "amazon ec2 nitro", files: map[string]string{
			"sys/class/dmi/id/sys_vendor":   "Amazon EC2\n",
			"sys/class/dmi/id/product_name": "m5.large\n",
		}, want: "amazon"},
		{name: "google compute engine", files: map[string]string{
			"sys/class/dmi/id/product_name": "Google Compute Engine\n",
		}, want: "google"},
		{name: "bochs", files: map[string]string{
			"sys/class/dmi/id/product_name": "Bochs\n",
		}, want: "bochs"},
		{name: "parallels", files: map[string]string{
			"sys/class/dmi/id/product_name": "Parallels Virtual Platform\n",
		}, want: "parallels"},
		{name: "unknown hypervisor type passed through", files: map[string]string{
			"sys/hypervisor/type": "acrn\n",
		}, want: "acrn"},
		{name: "docker marker file", files: map[string]string{
			".dockerenv":                    "",
			"sys/class/dmi/id/product_name": "KVM Virtual Machine\n",
		}, want: "docker"},
		{name: "podman marker file", files: map[string]string{
			"run/.containerenv": "engine=\"podman-5.0.0\"\n",
		}, want: "podman"},
		{name: "docker via init cgroup", files: map[string]string{
			"proc/1/cgroup": "12:pids:/docker/9f4b2c\n11:memory:/docker/9f4b2c\n",
		}, want: "docker"},
		{name: "lxc via init cgroup", files: map[string]string{
			"proc/1/cgroup": "0::/lxc.payload.mycontainer/init.scope\n",
		}, want: "lxc"},
		{name: "kubernetes via init cgroup", files: map[string]string{
			"proc/1/cgroup": "0::/kubepods/besteffort/podabc/xyz\n",
		}, want: "kubernetes"},
		{name: "host cgroup is not a container", files: map[string]string{
			"proc/1/cgroup": "0::/init.scope\n",
		}, want: ""},
		{name: "container beats the hypervisor it runs on", files: map[string]string{
			".dockerenv":          "",
			"sys/hypervisor/type": "xen\n",
		}, want: "docker"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := Collect(context.Background(), writeFixture(t, tc.files))
			if h.Virtualization != tc.want {
				t.Errorf("Virtualization = %q, want %q", h.Virtualization, tc.want)
			}
		})
	}
}

func TestCollectHostname(t *testing.T) {
	realHostname, _ := os.Hostname()

	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{name: "from etc hostname", files: map[string]string{"etc/hostname": "web01\n"}, want: "web01"},
		{name: "first line only", files: map[string]string{"etc/hostname": "web02\ngarbage\n"}, want: "web02"},
		{name: "whitespace trimmed", files: map[string]string{"etc/hostname": "  web03  \n"}, want: "web03"},
		{name: "falls back to os.Hostname", files: map[string]string{}, want: realHostname},
		{name: "empty file falls back", files: map[string]string{"etc/hostname": "\n"}, want: realHostname},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Collect(context.Background(), writeFixture(t, tc.files)).Hostname; got != tc.want {
				t.Errorf("Hostname = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCollectFixtureTreeIsOffline asserts that no fixture tree, however it is
// spelled, triggers DNS or interface enumeration.
func TestCollectFixtureTreeIsOffline(t *testing.T) {
	base := writeFixture(t, map[string]string{"etc/hostname": "offline-host\n"})
	for _, root := range []string{base, base + string(os.PathSeparator), filepath.Join(base, ".")} {
		h := Collect(context.Background(), root)
		if h.FQDN != "" || len(h.IPv4) != 0 || len(h.IPv6) != 0 || len(h.MACs) != 0 {
			t.Errorf("root %q produced network facts: %+v", root, h)
		}
		if h.Hostname != "offline-host" {
			t.Errorf("root %q: Hostname = %q, want %q", root, h.Hostname, "offline-host")
		}
	}
}

func TestCollectEmptyRootMeansSystemRoot(t *testing.T) {
	// An empty fsRoot is documented to mean "/", so this must behave exactly
	// like a real collection: the kernel hostname, not a fixture value.
	h := Collect(context.Background(), "")
	want, err := os.Hostname()
	if err != nil {
		t.Skipf("os.Hostname failed: %v", err)
	}
	if h.Hostname != want {
		t.Errorf("Hostname = %q, want %q", h.Hostname, want)
	}
	if h.Architecture != runtime.GOARCH {
		t.Errorf("Architecture = %q, want %q", h.Architecture, runtime.GOARCH)
	}
}

// TestCollectSystemRootIsSafe is the "must never fail" smoke test against the
// live machine: whatever the environment, Collect returns and the slices it
// produces are normalised.
func TestCollectSystemRootIsSafe(t *testing.T) {
	h := Collect(context.Background(), "/")

	if h.Architecture != runtime.GOARCH {
		t.Errorf("Architecture = %q, want %q", h.Architecture, runtime.GOARCH)
	}
	for _, s := range [][]string{h.IPv4, h.IPv6, h.MACs} {
		if !isSortedUniqueNonEmpty(s) {
			t.Errorf("slice %v is not sorted, deduplicated, and free of blanks", s)
		}
	}
	for _, ip := range append(append([]string(nil), h.IPv4...), h.IPv6...) {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Errorf("address %q does not parse", ip)
			continue
		}
		if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
			t.Errorf("address %q should have been filtered out", ip)
		}
	}
	if h.FQDN != "" && !strings.Contains(h.FQDN, ".") {
		t.Errorf("FQDN = %q, want a qualified name or nothing", h.FQDN)
	}
}

// TestCollectCancelledContext asserts the DNS deadline path is not fatal: a
// context that is already dead must still yield a fully populated local Host.
func TestCollectCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	h := Collect(ctx, "/")
	if h.Architecture != runtime.GOARCH {
		t.Errorf("Architecture = %q, want %q", h.Architecture, runtime.GOARCH)
	}
	if h.FQDN != "" && !strings.Contains(h.FQDN, ".") {
		t.Errorf("FQDN = %q, want a qualified name or nothing", h.FQDN)
	}
}

func TestUnquote(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"single character", `"`, `"`},
		{"bare word", "bare", "bare"},
		{"double quoted", `"x y"`, "x y"},
		{"single quoted", `'x y'`, "x y"},
		{"empty double quotes", `""`, ""},
		{"empty single quotes", `''`, ""},
		{"nested single inside double", `"it's"`, "it's"},
		{"nested double inside single", `'say "hi"'`, `say "hi"`},
		{"escape resolved", `"a\"b"`, `a"b`},
		{"single quotes do not unescape", `'a\nb'`, `a\nb`},
		{"unbalanced left", `"abc`, `"abc`},
		{"unbalanced right", `abc"`, `abc"`},
		{"only backslash inside quotes", `"\"`, `"\"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := unquote(tc.in); got != tc.want {
				t.Errorf("unquote(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeRoot(t *testing.T) {
	tests := []struct {
		in       string
		wantRoot string
		wantSys  bool
	}{
		{"", "/", true},
		{"   ", "/", true},
		{"/", "/", true},
		{"//", "/", true},
		{"/.", "/", true},
		{"/mnt/fixture", "/mnt/fixture", false},
		{"/mnt/fixture/", "/mnt/fixture", false},
		{"relative/tree", "relative/tree", false},
		{".", ".", false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			root, sys := normalizeRoot(tc.in)
			if root != tc.wantRoot || sys != tc.wantSys {
				t.Errorf("normalizeRoot(%q) = (%q, %v), want (%q, %v)",
					tc.in, root, sys, tc.wantRoot, tc.wantSys)
			}
		})
	}
}

func TestCanonicalName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"host", ""},
		{"host.", ""},
		{"host.example.com.", "host.example.com"},
		{"  HOST.Example.COM.  ", "host.example.com"},
		{".", ""},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := canonicalName(tc.in); got != tc.want {
				t.Errorf("canonicalName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCleanDMI(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"  Dell Inc.  \n", "Dell Inc."},
		{"To Be Filled By O.E.M.", ""},
		{"default string", ""},
		{"None", ""},
		{"00000000-0000-0000-0000-000000000000", ""},
		{"PowerEdge R640", "PowerEdge R640"},
		{"line1\nline2", "line1"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := cleanDMI(tc.in); got != tc.want {
				t.Errorf("cleanDMI(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestReadFileNeverFails(t *testing.T) {
	root := writeFixture(t, map[string]string{"a/b": "value\n"})
	tests := []struct{ name, rel, want string }{
		{"present", "a/b", "value"},
		{"missing", "a/nope", ""},
		{"directory", "a", ""},
		{"missing parent", "x/y/z", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := readFile(root, tc.rel); got != tc.want {
				t.Errorf("readFile(%q) = %q, want %q", tc.rel, got, tc.want)
			}
		})
	}
}

func TestReadFileIsTruncatedNotUnbounded(t *testing.T) {
	root := writeFixture(t, map[string]string{"big": strings.Repeat("a", maxFileSize+4096)})
	if got := len(readFile(root, "big")); got != maxFileSize {
		t.Errorf("readFile length = %d, want %d", got, maxFileSize)
	}
}

// isSortedUniqueNonEmpty mirrors the guarantee (*model.Host).Normalize makes.
func isSortedUniqueNonEmpty(s []string) bool {
	for i, v := range s {
		if v == "" {
			return false
		}
		if i > 0 && s[i-1] >= v {
			return false
		}
	}
	return true
}

func TestTrailingBackslashes(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 0},
		{`abc\`, 1},
		{`abc\\`, 2},
		{`\\\`, 3},
		{`a\b`, 0},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := trailingBackslashes(tc.in); got != tc.want {
				t.Errorf("trailingBackslashes(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
