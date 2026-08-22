package service

import (
	"encoding/binary"
	"testing"
)

// buildTable assembles a table buffer the way iphlpapi returns one: a DWORD
// count followed by fixed-size rows.
func buildTable(rows ...[]byte) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(len(rows)))
	for _, r := range rows {
		out = append(out, r...)
	}
	return out
}

func dword(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// netPortDWORD encodes a port the way the kernel does: network byte order in
// the low 16 bits, with the high 16 bits left as undefined rubbish that must
// be masked off rather than trusted.
func netPortDWORD(port uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:2], port)
	b[2], b[3] = 0xAB, 0xCD
	return b
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestParseTCPTable4(t *testing.T) {
	listening := concat(
		dword(mibTCPStateListen),
		[]byte{0, 0, 0, 0}, // 0.0.0.0, already network order
		netPortDWORD(443),
		[]byte{0, 0, 0, 0}, dword(0),
		dword(4242),
	)
	established := concat(
		dword(5), // MIB_TCP_STATE_ESTAB
		[]byte{127, 0, 0, 1}, netPortDWORD(51000),
		[]byte{93, 184, 216, 34}, netPortDWORD(443),
		dword(999),
	)
	loopback := concat(
		dword(mibTCPStateListen),
		[]byte{127, 0, 0, 1}, netPortDWORD(5432),
		[]byte{0, 0, 0, 0}, dword(0),
		dword(77),
	)

	got := parseTCPTable4(buildTable(listening, established, loopback))
	if len(got) != 2 {
		t.Fatalf("got %d sockets, want 2 (the established one is not a service)", len(got))
	}
	if got[0] != (winSocket{Protocol: TCP, Address: "0.0.0.0", Port: 443, PID: 4242}) {
		t.Errorf("first = %+v", got[0])
	}
	if got[1] != (winSocket{Protocol: TCP, Address: "127.0.0.1", Port: 5432, PID: 77}) {
		t.Errorf("second = %+v", got[1])
	}
}

func TestParseTCPTable6(t *testing.T) {
	unspecified := make([]byte, 16)
	row := concat(
		unspecified,
		dword(0), // local scope
		netPortDWORD(8080),
		make([]byte, 16), // remote addr
		dword(0),         // remote scope
		dword(0),         // remote port
		dword(mibTCPStateListen),
		dword(1234),
	)
	if len(row) != tcpRow6Size {
		t.Fatalf("test row is %d bytes, want %d", len(row), tcpRow6Size)
	}

	got := parseTCPTable6(buildTable(row))
	if len(got) != 1 {
		t.Fatalf("got %d sockets", len(got))
	}
	if got[0] != (winSocket{Protocol: TCP6, Address: "::", Port: 8080, PID: 1234}) {
		t.Errorf("got %+v", got[0])
	}
}

// UDP has no listening state, so every bound socket is reported.
func TestParseUDPTables(t *testing.T) {
	v4 := concat([]byte{0, 0, 0, 0}, netPortDWORD(53), dword(500))
	got4 := parseUDPTable4(buildTable(v4))
	if len(got4) != 1 || got4[0] != (winSocket{Protocol: UDP, Address: "0.0.0.0", Port: 53, PID: 500}) {
		t.Errorf("v4 = %+v", got4)
	}

	v6 := concat(make([]byte, 16), dword(0), netPortDWORD(5353), dword(501))
	if len(v6) != udpRow6Size {
		t.Fatalf("v6 test row is %d bytes, want %d", len(v6), udpRow6Size)
	}
	got6 := parseUDPTable6(buildTable(v6))
	if len(got6) != 1 || got6[0] != (winSocket{Protocol: UDP6, Address: "::", Port: 5353, PID: 501}) {
		t.Errorf("v6 = %+v", got6)
	}
}

// The count in the header is negotiated with the kernel between two calls, so
// a table that grows in between returns more rows than the buffer holds.
// Trusting the header would read past the end.
func TestTableRowsClampsAnOverstatedCount(t *testing.T) {
	raw := make([]byte, 4+tcpRow4Size)
	binary.LittleEndian.PutUint32(raw[0:4], 99)
	rows, n := tableRows(raw, tcpRow4Size)
	if n != 1 {
		t.Errorf("n = %d, want 1", n)
	}
	if len(rows) < tcpRow4Size {
		t.Errorf("rows = %d bytes", len(rows))
	}
	// And a buffer too small to hold a header at all yields nothing.
	if _, n := tableRows([]byte{1, 2}, tcpRow4Size); n != 0 {
		t.Errorf("n = %d for a truncated buffer", n)
	}
	if got := parseTCPTable4(nil); len(got) != 0 {
		t.Errorf("parseTCPTable4(nil) = %v", got)
	}
}
