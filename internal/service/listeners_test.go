package service

import (
	"strings"
	"testing"
)

// Lines below are verbatim from /proc/net on a live host.
const realTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:8B95 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 188093446 1 0000000000000000 100 0 0 10 0
   1: 00000000:1218 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 84979710 1 0000000000000000 100 0 0 10 0
   2: 0100007F:EA2C 0100007F:0143 01 00000000:00000000 00:00000000 00000000   982        0 202773595 2 0000000000000000 0
`

func TestParseNetTableIPv4(t *testing.T) {
	got, err := ParseNetTable(strings.NewReader(realTCP), TCP)
	if err != nil {
		t.Fatal(err)
	}
	// The third row is an established connection, not a listener.
	if len(got) != 2 {
		t.Fatalf("got %d endpoints, want 2 listeners", len(got))
	}

	// 0100007F is 127.0.0.1: the kernel writes each 32-bit word in host order,
	// so on a little-endian machine the address reads back to front. Decoding
	// it as a plain hex string gives 1.0.0.127, which is a real-looking
	// address belonging to someone else.
	if got[0].Address != "127.0.0.1" {
		t.Errorf("address = %q, want 127.0.0.1", got[0].Address)
	}
	if got[0].Port != 0x8B95 {
		t.Errorf("port = %d, want %d", got[0].Port, 0x8B95)
	}
	if got[0].Inode != 188093446 {
		t.Errorf("inode = %d", got[0].Inode)
	}
	if got[1].Address != "0.0.0.0" {
		t.Errorf("address = %q, want 0.0.0.0", got[1].Address)
	}
}

const realTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1FBD 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   982        0 20277 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 20278 1 0000000000000000 100 0 0 10 0
`

func TestParseNetTableIPv6(t *testing.T) {
	got, err := ParseNetTable(strings.NewReader(realTCP6), TCP6)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(got))
	}
	// Sixteen bytes as four little-endian words, not one long hex string.
	if got[0].Address != "::1" {
		t.Errorf("address = %q, want ::1", got[0].Address)
	}
	if got[1].Address != "::" || got[1].Port != 80 {
		t.Errorf("got %s, want [::]:80", got[1])
	}
}

// UDP has no listen state, so a bound socket is one with no peer. The second
// row here is a client conversation and must not be reported as serving.
const realUDP = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 1963: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 30001 2 0000000000000000 0
 1964: 0100007F:EA2C 0100007F:0143 01 00000000:00000000 00:00000000 00000000   982        0 202773595 2 0000000000000000 0
`

func TestParseNetTableUDP(t *testing.T) {
	got, err := ParseNetTable(strings.NewReader(realUDP), UDP)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d endpoints, want 1 bound socket", len(got))
	}
	if got[0].Port != 53 {
		t.Errorf("port = %d, want 53", got[0].Port)
	}
}

func TestEndpointString(t *testing.T) {
	cases := map[string]Endpoint{
		"0.0.0.0:443/tcp":  {Protocol: TCP, Address: "0.0.0.0", Port: 443},
		"[::]:443/tcp6":    {Protocol: TCP6, Address: "::", Port: 443},
		"127.0.0.1:53/udp": {Protocol: UDP, Address: "127.0.0.1", Port: 53},
	}
	for want, e := range cases {
		if got := e.String(); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

// Malformed rows are skipped rather than aborting the table: /proc is read
// while the kernel is changing it, and one unreadable row must not cost the
// rest of the machine's listeners.
func TestParseNetTableSkipsMalformed(t *testing.T) {
	in := `header
   0: garbage 00000000:0000 0A x x x x x 12345
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 999 1
   2: tooshort
`
	got, err := ParseNetTable(strings.NewReader(in), TCP)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Port != 80 {
		t.Errorf("got %v, want only the well-formed listener on port 80", got)
	}
}

// The cgroup lines below are verbatim from a live host, including a Docker
// container's scope.
func TestUnitFromCgroup(t *testing.T) {
	cases := []struct {
		name, in, unit, container string
	}{
		{"a systemd service", "0::/system.slice/nginx.service\n", "nginx.service", ""},
		{"a container scope",
			"0::/system.slice/docker-9d5a98d0dc04ca4435668f83ff17cb7225536f2ca81d15014ee42edc9a42f9bb.scope\n",
			"", "9d5a98d0dc04ca4435668f83ff17cb7225536f2ca81d15014ee42edc9a42f9bb"},
		{"init itself", "0::/init.scope\n", "init.scope", ""},
		{"a user session", "0::/user.slice/user-1000.slice/session-3.scope\n", "session-3.scope", ""},
		{"cgroup v1 with a controller list", "12:pids:/system.slice/sshd.service\n", "sshd.service", ""},
		{"a socket unit", "0::/system.slice/docker.socket\n", "docker.socket", ""},
		{"podman", "0::/machine.slice/libpod-abc123def456.scope\n", "", "abc123def456"},
		{"nothing recognisable", "0::/\n", "", ""},
		{"empty", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unit, container := UnitFromCgroup(strings.NewReader(tc.in))
			if unit != tc.unit || container != tc.container {
				t.Errorf("got unit=%q container=%q, want unit=%q container=%q",
					unit, container, tc.unit, tc.container)
			}
		})
	}
}
