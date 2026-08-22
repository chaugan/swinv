package service

import (
	"net"
	"strings"
)

// parseFibTrieLocal extracts the IPv4 addresses a namespace has assigned, from
// the "Local:" table of /proc/<pid>/net/fib_trie.
//
// The format is a printed trie: a leaf line names an address and the line
// after it gives that address's prefix and type.
//
//	   |-- 172.25.0.2
//	      /32 host LOCAL
//	|-- 172.25.255.255
//	   /32 host BROADCAST
//
// Only "LOCAL" entries are addresses the namespace answers on; BROADCAST and
// UNICAST route entries are not. Loopback is dropped because every namespace
// has it and it joins nothing.
//
// This is debug output and its format is not a kernel interface, which is why
// every caller treats an empty result as ordinary.
func parseFibTrieLocal(raw string) []string {
	var (
		out     []string
		seen    = map[string]bool{}
		lastIP  string
		inLocal bool
	)
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Local:"):
			inLocal = true
			continue
		case strings.HasPrefix(trimmed, "Main:"):
			// The main table repeats routes; only Local names assigned
			// addresses.
			inLocal = false
			continue
		}
		if !inLocal {
			continue
		}

		if addr, ok := strings.CutPrefix(trimmed, "|-- "); ok {
			lastIP = strings.TrimSpace(addr)
			continue
		}
		if addr, ok := strings.CutPrefix(trimmed, "+-- "); ok {
			// A branch line carries a prefix, not an address.
			_ = addr
			lastIP = ""
			continue
		}
		if lastIP == "" || !strings.HasSuffix(trimmed, "LOCAL") {
			continue
		}

		ip := net.ParseIP(lastIP)
		lastIP = ""
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		if s := ip.String(); !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
