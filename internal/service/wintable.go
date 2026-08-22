package service

import (
	"encoding/binary"
	"net"
)

// The MIB_*_OWNER_PID row layouts, from iphlpapi.h. Parsed here as plain bytes
// rather than as Go structs over a returned pointer, so the layouts are
// exercised by tests on any platform -- getting a field offset wrong would
// otherwise be discoverable only on Windows, and only by noticing that the
// ports look absurd.
const (
	tcpRow4Size = 24 // state, localAddr, localPort, remoteAddr, remotePort, pid
	tcpRow6Size = 56 // localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid
	udpRow4Size = 12 // localAddr, localPort, pid
	udpRow6Size = 28 // localAddr[16], localScope, localPort, pid
)

// mibTCPStateListen is MIB_TCP_STATE_LISTEN. Only listening sockets are
// reported; an established connection is a fact about traffic, not about what
// this machine offers.
const mibTCPStateListen = 2

// parseTCPTable4 reads a MIB_TCPTABLE_OWNER_PID buffer.
//
// The table begins with a DWORD count. Addresses are in network byte order and
// ports occupy the low 16 bits of a DWORD, also in network byte order -- the
// high 16 bits are undefined and must be masked off rather than trusted.
func parseTCPTable4(raw []byte) []winSocket {
	rows, n := tableRows(raw, tcpRow4Size)
	out := make([]winSocket, 0, n)
	for i := 0; i < n; i++ {
		row := rows[i*tcpRow4Size : (i+1)*tcpRow4Size]
		if binary.LittleEndian.Uint32(row[0:4]) != mibTCPStateListen {
			continue
		}
		out = append(out, winSocket{
			Protocol: TCP,
			Address:  ipv4String(row[4:8]),
			Port:     netPort(row[8:12]),
			PID:      int(binary.LittleEndian.Uint32(row[20:24])),
		})
	}
	return out
}

// parseTCPTable6 reads a MIB_TCP6TABLE_OWNER_PID buffer.
func parseTCPTable6(raw []byte) []winSocket {
	rows, n := tableRows(raw, tcpRow6Size)
	out := make([]winSocket, 0, n)
	for i := 0; i < n; i++ {
		row := rows[i*tcpRow6Size : (i+1)*tcpRow6Size]
		if binary.LittleEndian.Uint32(row[48:52]) != mibTCPStateListen {
			continue
		}
		out = append(out, winSocket{
			Protocol: TCP6,
			Address:  ipv6String(row[0:16]),
			Port:     netPort(row[20:24]),
			PID:      int(binary.LittleEndian.Uint32(row[52:56])),
		})
	}
	return out
}

// parseUDPTable4 reads a MIB_UDPTABLE_OWNER_PID buffer.
//
// UDP has no listening state, so every bound socket is reported. "Bound" is a
// weaker claim than "listening" and the report says so by carrying the
// protocol; a consumer treating a bound UDP socket as a service should weigh
// it accordingly.
func parseUDPTable4(raw []byte) []winSocket {
	rows, n := tableRows(raw, udpRow4Size)
	out := make([]winSocket, 0, n)
	for i := 0; i < n; i++ {
		row := rows[i*udpRow4Size : (i+1)*udpRow4Size]
		out = append(out, winSocket{
			Protocol: UDP,
			Address:  ipv4String(row[0:4]),
			Port:     netPort(row[4:8]),
			PID:      int(binary.LittleEndian.Uint32(row[8:12])),
		})
	}
	return out
}

// parseUDPTable6 reads a MIB_UDP6TABLE_OWNER_PID buffer.
func parseUDPTable6(raw []byte) []winSocket {
	rows, n := tableRows(raw, udpRow6Size)
	out := make([]winSocket, 0, n)
	for i := 0; i < n; i++ {
		row := rows[i*udpRow6Size : (i+1)*udpRow6Size]
		out = append(out, winSocket{
			Protocol: UDP6,
			Address:  ipv6String(row[0:16]),
			Port:     netPort(row[20:24]),
			PID:      int(binary.LittleEndian.Uint32(row[24:28])),
		})
	}
	return out
}

// winSocket is one row of an iphlpapi table, before it is joined to a process.
type winSocket struct {
	Protocol Protocol
	Address  string
	Port     uint16
	PID      int
}

// tableRows returns the row area of a table buffer and how many whole rows it
// holds, clamped to what was actually returned.
//
// The count in the header is trusted only as far as the buffer allows. A
// truncated read would otherwise index past the end -- and the buffer size is
// negotiated with the kernel between two calls, so a table that grows between
// them is an ordinary race, not a corrupt result.
func tableRows(raw []byte, rowSize int) ([]byte, int) {
	if len(raw) < 4 {
		return nil, 0
	}
	claimed := int(binary.LittleEndian.Uint32(raw[0:4]))
	rows := raw[4:]
	available := len(rows) / rowSize
	if claimed > available {
		claimed = available
	}
	if claimed < 0 {
		return nil, 0
	}
	return rows, claimed
}

// netPort reads a port from the low 16 bits of a DWORD in network byte order.
func netPort(b []byte) uint16 {
	return binary.BigEndian.Uint16(b[0:2])
}

func ipv4String(b []byte) string {
	return net.IP(b[0:4]).String()
}

func ipv6String(b []byte) string {
	return net.IP(b[0:16]).String()
}
