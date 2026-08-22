package service

import "testing"

func TestParseDockerProxy(t *testing.T) {
	got, ok := ParseDockerProxy(
		"/usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 3000 " +
			"-container-ip 172.17.0.2 -container-port 3000 -use-listen-fd")
	if !ok {
		t.Fatal("did not parse a real docker-proxy command line")
	}
	want := Forward{
		HostAddress: "0.0.0.0", HostPort: 3000, Protocol: "tcp",
		BackendAddress: "172.17.0.2", BackendPort: 3000, Via: "docker-proxy-argv",
	}
	if got != want {
		t.Errorf("ParseDockerProxy = %+v, want %+v", got, want)
	}
}

// A loopback-published port is a different finding from a world-published one,
// and the distinction is in the argv.
func TestParseDockerProxyLoopback(t *testing.T) {
	got, ok := ParseDockerProxy(
		"/usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 4620 " +
			"-container-ip 172.23.0.2 -container-port 4620 -use-listen-fd")
	if !ok || got.HostAddress != "127.0.0.1" {
		t.Errorf("ParseDockerProxy = %+v, ok=%v", got, ok)
	}
}

// A partial or unfamiliar command line must yield nothing rather than a
// half-filled forward that would point at the wrong place.
func TestParseDockerProxyRefusesIncomplete(t *testing.T) {
	for _, in := range []string{
		"/usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 3000",
		"/usr/bin/docker-proxy",
		"",
		"/usr/bin/rootlessport",
	} {
		if got, ok := ParseDockerProxy(in); ok {
			t.Errorf("ParseDockerProxy(%q) = %+v, want refusal", in, got)
		}
	}
}

func TestIsForwarder(t *testing.T) {
	for _, exe := range []string{"/usr/bin/docker-proxy", "/usr/bin/rootlessport", "/usr/bin/pasta"} {
		if _, ok := IsForwarder(exe); !ok {
			t.Errorf("IsForwarder(%q) = false; its package is not the software behind the port", exe)
		}
	}
	for _, exe := range []string{"/usr/sbin/nginx", "", "/usr/bin/docker"} {
		if runtime, ok := IsForwarder(exe); ok {
			t.Errorf("IsForwarder(%q) = %q; an ordinary daemon must keep its own attribution", exe, runtime)
		}
	}
}
