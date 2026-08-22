package service

import (
	"net"

	"github.com/chaugan/swinv/internal/model"
)

// BindScopeOf classifies a bound address.
//
// It describes the bind and nothing else. swinv reads no firewall, no NAT
// table and no cloud security group, so any vocabulary implying reachability
// would be a claim it cannot support -- which is why there is no "public" and
// no "internet-facing" here, and why a routable address is only ever
// "specific". The address itself is always kept in the record, so a consumer
// with an actual network model can classify it further; the reverse is not
// possible.
func BindScopeOf(address string) model.BindScope {
	ip := net.ParseIP(address)
	if ip == nil {
		return model.BindSpecific
	}
	switch {
	case ip.IsUnspecified():
		return model.BindWildcard
	case ip.IsLoopback():
		return model.BindLoopback
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return model.BindLinkLocal
	default:
		return model.BindSpecific
	}
}

// familyOf reports the address family an endpoint was read from.
//
// Taken from the table the socket appeared in rather than from the address
// text, because Go renders an IPv4-mapped IPv6 address as a dotted quad: a
// row from /proc/net/tcp6 can print "127.0.0.1", and a consumer counting IPv4
// exposure by looking at the address would disagree with one counting by
// protocol.
func familyOf(p Protocol) string {
	switch p {
	case TCP6, UDP6:
		return "ipv6"
	default:
		return "ipv4"
	}
}

// transportOf strips the address family from the protocol, so that "tcp6"
// becomes "tcp" and the family lives in its own field.
func transportOf(p Protocol) string {
	switch p {
	case TCP, TCP6:
		return "tcp"
	default:
		return "udp"
	}
}
