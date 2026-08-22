package service

import (
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

func TestBindScopeOf(t *testing.T) {
	cases := map[string]model.BindScope{
		"0.0.0.0":     model.BindWildcard,
		"::":          model.BindWildcard,
		"127.0.0.1":   model.BindLoopback,
		"127.0.0.53":  model.BindLoopback,
		"::1":         model.BindLoopback,
		"169.254.1.1": model.BindLinkLocal,
		"fe80::1":     model.BindLinkLocal,
		// Routable, and deliberately not split into private and public: swinv
		// cannot tell a lab bridge from a flat datacentre L2, and "private"
		// would be read as "therefore safe".
		"10.1.0.136":  model.BindSpecific,
		"192.168.1.5": model.BindSpecific,
		"93.184.on":   model.BindSpecific,
		"2001:db8::1": model.BindSpecific,
	}
	for in, want := range cases {
		if got := BindScopeOf(in); got != want {
			t.Errorf("BindScopeOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// A tcp6 row can render as a dotted quad, so the family must come from the
// table the socket was read from rather than from the text of the address.
func TestFamilyAndTransport(t *testing.T) {
	cases := []struct {
		p                 Protocol
		family, transport string
	}{
		{TCP, "ipv4", "tcp"},
		{TCP6, "ipv6", "tcp"},
		{UDP, "ipv4", "udp"},
		{UDP6, "ipv6", "udp"},
	}
	for _, c := range cases {
		if got := familyOf(c.p); got != c.family {
			t.Errorf("familyOf(%q) = %q, want %q", c.p, got, c.family)
		}
		if got := transportOf(c.p); got != c.transport {
			t.Errorf("transportOf(%q) = %q, want %q", c.p, got, c.transport)
		}
	}
}
