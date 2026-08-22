package service

import (
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

func endpoint(addr string, port uint16, proto Protocol, inode uint64) Endpoint {
	return Endpoint{Protocol: proto, Address: addr, Port: port, Inode: inode}
}

func hostService(pid int, exe string, eps ...Endpoint) Service {
	return Service{
		Process:     Process{PID: pid, Exe: exe},
		Endpoints:   eps,
		HostNetwork: true,
	}
}

// One row per socket, and the bind scope taken from the address rather than
// invented.
func TestExposeOneRowPerSocket(t *testing.T) {
	r := &Result{Services: []Service{
		hostService(811, "/usr/sbin/sshd",
			endpoint("0.0.0.0", 22, TCP, 1),
			endpoint("::", 22, TCP6, 2)),
		hostService(900, "/usr/lib/postgresql/18/bin/postgres",
			endpoint("127.0.0.1", 5432, TCP, 3)),
	}}
	attributed := []model.Service{
		{PID: 811, Components: []string{"pkg:deb/ubuntu/openssh-server@1"}, Confidence: model.ConfidenceHigh,
			Evidence: []string{"socket ...", "owned by openssh-server"}},
		{PID: 900, Confidence: model.ConfidenceMedium},
	}

	got := Expose(r, attributed, nil)
	if len(got) != 3 {
		t.Fatalf("got %d rows, want 3", len(got))
	}

	byPort := map[uint16][]model.Exposure{}
	for _, e := range got {
		byPort[e.Port] = append(byPort[e.Port], e)
	}
	if len(byPort[22]) != 2 {
		t.Errorf("port 22 produced %d rows", len(byPort[22]))
	}
	for _, e := range byPort[22] {
		if e.BindScope != model.BindWildcard {
			t.Errorf("0.0.0.0/:: bind_scope = %q", e.BindScope)
		}
		if len(e.Components) != 1 {
			t.Errorf("components = %v", e.Components)
		}
	}
	if byPort[5432][0].BindScope != model.BindLoopback {
		t.Errorf("127.0.0.1 bind_scope = %q", byPort[5432][0].BindScope)
	}
	// A "::" bind accepts IPv4 too on a default kernel, and a consumer
	// counting IPv4 exposure by family would otherwise undercount.
	for _, e := range byPort[22] {
		if e.Family == "ipv6" && !e.WildcardCoversIPv4 {
			t.Error("a :: wildcard did not record that it covers IPv4")
		}
	}
}

// A socket held by init *and* by the daemon init activated is one port, not
// two, and the row kept must be the one that names the daemon.
func TestExposeCollapsesASocketHeldTwice(t *testing.T) {
	shared := endpoint("0.0.0.0", 22, TCP, 77)
	r := &Result{Services: []Service{
		hostService(1, "/usr/lib/systemd/systemd", shared),
		hostService(811, "/usr/sbin/sshd", shared),
	}}
	attributed := []model.Service{
		{PID: 1, Confidence: model.ConfidenceLow},
		{PID: 811, Components: []string{"pkg:deb/ubuntu/openssh-server@1"}, Confidence: model.ConfidenceHigh},
	}

	got := Expose(r, attributed, nil)
	if len(got) != 1 {
		t.Fatalf("got %d rows for one socket: %+v", len(got), got)
	}
	if got[0].Executable != "/usr/sbin/sshd" || got[0].Confidence != model.ConfidenceHigh {
		t.Errorf("kept the less informative row: %+v", got[0])
	}
}

// The whole point. docker-proxy holds the socket, but its package is not the
// software behind the port -- that was 14 of 31 services on a real host.
func TestExposeNeverAttributesAPublishedPortToTheForwarder(t *testing.T) {
	r := &Result{
		Services: []Service{{
			Process: Process{
				PID: 2562, Exe: "/usr/bin/docker-proxy",
				Command: "/usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 3000 " +
					"-container-ip 172.17.0.2 -container-port 3000 -use-listen-fd",
			},
			Endpoints:   []Endpoint{endpoint("0.0.0.0", 3000, TCP, 9)},
			HostNetwork: true,
		}},
		Containers: []Container{{
			ID:        "df613448bf6ab0fbd2050e042709453eb7765fe5d035a32addb74fd8ef710c6a",
			Addresses: []string{"172.17.0.2"},
			Services: []Service{{
				Process:   Process{PID: 4000, Exe: "/usr/sbin/nginx"},
				Endpoints: []Endpoint{endpoint("0.0.0.0", 3000, TCP, 55)},
			}},
		}},
	}
	// docker-proxy's own attribution, which must not be inherited.
	attributed := []model.Service{{
		PID: 2562, Components: []string{"pkg:deb/ubuntu/docker-ce@5"}, Confidence: model.ConfidenceHigh,
	}}
	containers := []model.Container{{
		ID:    "df613448bf6ab0fbd2050e042709453eb7765fe5d035a32addb74fd8ef710c6a",
		Image: &model.Image{Ref: "nginx:alpine"},
		Services: []model.Service{{
			Executable: "/usr/sbin/nginx",
			Endpoints:  []string{"0.0.0.0:3000/tcp"},
			Components: []string{"pkg:apk/alpine/nginx@1.27.5-r1"},
			Confidence: model.ConfidenceHigh,
		}},
	}}

	got := Expose(r, attributed, containers)
	if len(got) != 1 {
		t.Fatalf("got %d rows", len(got))
	}
	e := got[0]
	for _, c := range e.Components {
		if c == "pkg:deb/ubuntu/docker-ce@5" {
			t.Fatal("the published port was attributed to the package that ships docker-proxy")
		}
	}
	if len(e.Components) != 1 || e.Components[0] != "pkg:apk/alpine/nginx@1.27.5-r1" {
		t.Errorf("components = %v, want the container's nginx", e.Components)
	}
	if e.Backend == nil || e.Backend.Address != "172.17.0.2" || e.Backend.Executable != "/usr/sbin/nginx" {
		t.Errorf("backend = %+v", e.Backend)
	}
	if e.Image == nil || e.Image.Ref != "nginx:alpine" {
		t.Errorf("image = %+v", e.Image)
	}
	// And the container's own service records where it is published.
	if len(containers[0].Services[0].PublishedAs) != 1 {
		t.Errorf("published_as = %v", containers[0].Services[0].PublishedAs)
	}
}

// When the forward cannot be followed, no identity is invented -- and the
// forwarder's own package is still not used.
func TestExposeForwarderWithNoResolvableBackend(t *testing.T) {
	r := &Result{Services: []Service{{
		Process: Process{PID: 2562, Exe: "/usr/bin/docker-proxy",
			Command: "/usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 3000 " +
				"-container-ip 172.17.0.9 -container-port 3000"},
		Endpoints:   []Endpoint{endpoint("0.0.0.0", 3000, TCP, 9)},
		HostNetwork: true,
	}}}
	attributed := []model.Service{{PID: 2562, Components: []string{"pkg:deb/ubuntu/docker-ce@5"}, Confidence: model.ConfidenceHigh}}

	got := Expose(r, attributed, nil)[0]
	if len(got.Components) != 0 {
		t.Errorf("components = %v, want none", got.Components)
	}
	if got.Confidence != model.ConfidenceLow {
		t.Errorf("confidence = %q, want low", got.Confidence)
	}
}

// Several containers listening on the same port is ordinary; picking one would
// be a coin flip presented as a finding.
func TestMatchBackendRefusesAnAmbiguousPortMatch(t *testing.T) {
	r := &Result{Containers: []Container{
		{ID: "aaa", Services: []Service{{Endpoints: []Endpoint{endpoint("0.0.0.0", 8080, TCP, 1)}}}},
		{ID: "bbb", Services: []Service{{Endpoints: []Endpoint{endpoint("0.0.0.0", 8080, TCP, 2)}}}},
	}}
	if got := matchBackend(r, Forward{BackendAddress: "172.20.0.9", BackendPort: 8080}); got != nil {
		t.Errorf("matchBackend picked %q from two candidates", got.ID)
	}

	// With an address it is not ambiguous at all.
	r.Containers[1].Addresses = []string{"172.20.0.9"}
	if got := matchBackend(r, Forward{BackendAddress: "172.20.0.9", BackendPort: 8080}); got == nil || got.ID != "bbb" {
		t.Errorf("matchBackend = %+v, want bbb", got)
	}
}

// Container listeners must never reach the host exposure list: a bind to
// 0.0.0.0 inside a container is not reachable at this machine's addresses.
func TestExposeIgnoresContainerNamespaces(t *testing.T) {
	r := &Result{
		Services: []Service{hostService(1, "/usr/lib/systemd/systemd", endpoint("127.0.0.1", 53, UDP, 1))},
		Containers: []Container{{
			ID:       "aaa",
			Services: []Service{{Process: Process{PID: 500, Exe: "/usr/sbin/nginx"}, Endpoints: []Endpoint{endpoint("0.0.0.0", 8080, TCP, 2)}}},
		}},
	}
	for _, e := range Expose(r, nil, nil) {
		if e.Port == 8080 {
			t.Errorf("a container-namespace listener appeared in the host exposure list: %+v", e)
		}
	}
}
