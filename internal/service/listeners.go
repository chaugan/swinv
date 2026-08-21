// Package service reports what is listening on a machine, and which installed
// software is behind it.
//
// An installed package and a listening service are different risk statements.
// nginx present in dpkg is a patch obligation; nginx bound to 0.0.0.0:443 is an
// exposure, and nothing in a package database says which. The gap runs both
// ways, and the more interesting direction is software that is *running but not
// installed* -- an application server unpacked into /opt, a vendor binary, a
// container with its own userspace -- which package inventory cannot see at all.
//
// Everything here is read from /proc. No ss, no netstat, no lsof, no D-Bus:
// those are absent from minimal containers and hardened hosts, which are
// exactly the machines worth asking about.
package service

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Protocol is the transport a socket is bound to.
type Protocol string

const (
	TCP  Protocol = "tcp"
	TCP6 Protocol = "tcp6"
	UDP  Protocol = "udp"
	UDP6 Protocol = "udp6"
)

// tcpListen is the state value for a TCP socket in LISTEN, from the kernel's
// TCP_LISTEN.
const tcpListen = 0x0A

// Endpoint is one socket accepting traffic.
type Endpoint struct {
	Protocol Protocol
	Address  string
	Port     uint16

	// Inode is the socket inode, which is the only join between this table and
	// the process that owns it: /proc/<pid>/fd entries are symlinks reading
	// "socket:[<inode>]".
	Inode uint64
}

// String renders an endpoint the way an operator writes one.
func (e Endpoint) String() string {
	if strings.Contains(e.Address, ":") {
		return fmt.Sprintf("[%s]:%d/%s", e.Address, e.Port, e.Protocol)
	}
	return fmt.Sprintf("%s:%d/%s", e.Address, e.Port, e.Protocol)
}

// ParseNetTable reads one of /proc/net/{tcp,tcp6,udp,udp6} and returns the
// sockets that are accepting traffic.
//
// TCP is unambiguous: a socket in LISTEN is listening. UDP has no such state,
// so a socket with no remote peer is taken as bound and serving. That is the
// best signal available and it is marked as such by its protocol, rather than
// being presented as equivalent to a TCP listener.
func ParseNetTable(r io.Reader, proto Protocol) ([]Endpoint, error) {
	var out []Endpoint

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for line := 0; scanner.Scan(); line++ {
		if line == 0 {
			continue // column headings
		}

		fields := strings.Fields(scanner.Text())
		// sl, local, remote, state, ..., inode is the tenth column.
		if len(fields) < 10 {
			continue
		}

		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			continue
		}
		if !accepting(proto, state, fields[2]) {
			continue
		}

		addr, port, err := parseAddress(fields[1], proto)
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}

		out = append(out, Endpoint{Protocol: proto, Address: addr, Port: port, Inode: inode})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("service: reading %s table: %w", proto, err)
	}
	return out, nil
}

// accepting decides whether a row describes a socket that serves.
func accepting(proto Protocol, state uint64, remote string) bool {
	switch proto {
	case TCP, TCP6:
		return state == tcpListen
	case UDP, UDP6:
		// No listen state exists. A datagram socket with no peer is bound and
		// will accept from anywhere; one with a peer is a client conversation.
		return strings.HasSuffix(remote, ":0000")
	}
	return false
}

// parseAddress decodes the kernel's hexadecimal address:port form.
//
// The bytes are in host order within each 32-bit word, so on a little-endian
// machine an IPv4 address reads back-to-front: 0100007F is 127.0.0.1. IPv6 is
// the same rule applied to four consecutive words, which is why it cannot be
// decoded as one long hex string.
func parseAddress(field string, proto Protocol) (string, uint16, error) {
	hexAddr, hexPort, ok := strings.Cut(field, ":")
	if !ok {
		return "", 0, fmt.Errorf("service: %q is not address:port", field)
	}

	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("service: port %q: %w", hexPort, err)
	}

	raw, err := decodeHexWords(hexAddr)
	if err != nil {
		return "", 0, err
	}

	switch proto {
	case TCP, UDP:
		if len(raw) != 4 {
			return "", 0, fmt.Errorf("service: %q is not a 4-byte address", hexAddr)
		}
	case TCP6, UDP6:
		if len(raw) != 16 {
			return "", 0, fmt.Errorf("service: %q is not a 16-byte address", hexAddr)
		}
	}
	return net.IP(raw).String(), uint16(port), nil
}

// decodeHexWords turns the kernel's hex address into bytes, reversing each
// 32-bit word.
func decodeHexWords(s string) ([]byte, error) {
	if len(s)%8 != 0 || len(s) == 0 {
		return nil, fmt.Errorf("service: address %q is not a whole number of 32-bit words", s)
	}

	out := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 8 {
		word, err := strconv.ParseUint(s[i:i+8], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("service: address word %q: %w", s[i:i+8], err)
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(word))
		out = append(out, b[:]...)
	}
	return out, nil
}
