package service

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// Expose turns the host namespace's listeners into one row per socket, with
// the identity of the software actually behind each.
//
// One row per socket rather than per process because that is the unit of the
// question: "is this port a problem" is asked of a port, and a process bound
// to four sockets can be four different answers -- three on loopback and one
// on the world.
//
// containers is consulted for two things: to name the software behind a
// published port, and to record on that container's service which host
// endpoints publish it.
func Expose(r *Result, attributed []model.Service, containers []model.Container) []model.Exposure {
	if r == nil {
		return nil
	}
	byPID := make(map[int]model.Service, len(attributed))
	for _, s := range attributed {
		if s.PID != 0 {
			byPID[s.PID] = s
		}
	}

	// One row per socket, not per (socket, holder). A socket-activated port is
	// held by init *and* by the daemon init started, and reporting it twice
	// would double every count built on this -- while leaving a reader to
	// guess which of two rows for port 22 to believe.
	var out []model.Exposure
	byInode := make(map[uint64]int, len(r.Services))
	for _, s := range r.Services {
		runtime, forwards := IsForwarder(s.Process.Exe)
		for _, e := range s.Endpoints {
			row := exposeOne(s, e, byPID[s.Process.PID], runtime, forwards, r, containers)
			if at, seen := byInode[e.Inode]; seen && e.Inode != 0 {
				if better(row, out[at]) {
					out[at] = row
				}
				continue
			}
			byInode[e.Inode] = len(out)
			out = append(out, row)
		}
	}

	// A socket whose holder could not be identified is still an open port.
	// Leaving it out would report a machine as having nothing exposed on the
	// strength of not having been able to look -- which is the failure this
	// whole section is built to avoid, and which a privileged WSL2 run hit
	// while reporting twelve listening sockets and zero exposure rows.
	for _, e := range r.Unowned {
		if _, seen := byInode[e.Inode]; seen && e.Inode != 0 {
			continue
		}
		row := model.Exposure{
			Address:    e.Address,
			Port:       e.Port,
			Protocol:   transportOf(e.Protocol),
			Family:     familyOf(e.Protocol),
			BindScope:  BindScopeOf(e.Address),
			Confidence: model.ConfidenceLow,
			Evidence: []string{
				fmt.Sprintf("socket %s is open in the host network namespace", e),
				"the process holding it could not be identified: either another user's " +
					"open files were unreadable, which needs root, or the holder is " +
					"outside this PID namespace",
			},
		}
		if row.BindScope == model.BindWildcard && row.Family == "ipv6" {
			row.WildcardCoversIPv4 = true
		}
		byInode[e.Inode] = len(out)
		out = append(out, row)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func exposeOne(s Service, e Endpoint, attributed model.Service, runtime string, forwards bool,
	r *Result, containers []model.Container) model.Exposure {

	out := model.Exposure{
		Address:    e.Address,
		Port:       e.Port,
		Protocol:   transportOf(e.Protocol),
		Family:     familyOf(e.Protocol),
		BindScope:  BindScopeOf(e.Address),
		PID:        s.Process.PID,
		Executable: s.Process.Exe,
		Unit:       s.Process.Unit,
		User:       s.Process.User,
		Container:  s.Process.Container,
		Evidence:   []string{fmt.Sprintf("socket %s held by pid %d in the host network namespace", e, s.Process.PID)},
	}

	// A "::" bind on a kernel with bindv6only off accepts IPv4 too. Without
	// saying so, a consumer counting IPv4 exposure by family undercounts.
	if out.BindScope == model.BindWildcard && out.Family == "ipv6" {
		out.WildcardCoversIPv4 = true
	}

	if !forwards {
		out.Components = attributed.Components
		out.Confidence = attributed.Confidence
		if out.Confidence == "" {
			out.Confidence = model.ConfidenceLow
		}
		// The attributed service's own evidence, minus its first line: that is
		// the socket line, which this row has already stated for this one
		// socket rather than for all of the process's.
		if len(attributed.Evidence) > 1 {
			out.Evidence = append(out.Evidence, attributed.Evidence[1:]...)
		}
		return out
	}

	// The socket is held on behalf of something else. Its own package is not
	// the answer -- naming docker-ce as the software behind a published port
	// is true and useless, and it was 14 of 31 services on the development
	// host -- so no attribution is inherited here, ever.
	out.Evidence = append(out.Evidence, fmt.Sprintf(
		"held by %s, which forwards for %s, so its own package is not the software behind this port",
		s.Process.Exe, runtime))

	// A mapping the runtime itself stated beats one parsed out of a command
	// line, and on Windows it is the only one available.
	if p, ok := publishFor(r, e); ok {
		return withBackend(out, r, containers, Forward{
			BackendAddress: "", BackendPort: p.ContainerPort, Via: p.Via,
		}, p.ContainerID, e)
	}

	forward, ok := ParseDockerProxy(s.Process.Command)
	if !ok {
		out.Confidence = model.ConfidenceLow
		out.Evidence = append(out.Evidence,
			"the forward destination could not be read from its command line")
		return out
	}
	out.Backend = &model.Backend{
		Address: forward.BackendAddress,
		Port:    forward.BackendPort,
		Via:     forward.Via,
	}

	target := matchBackend(r, forward)
	if target == nil {
		out.Confidence = model.ConfidenceLow
		out.Evidence = append(out.Evidence, fmt.Sprintf(
			"no container was found listening on %s:%d", forward.BackendAddress, forward.BackendPort))
		return out
	}
	return withBackend(out, r, containers, forward, target.ID, e)
}

// publishFor finds a runtime-stated mapping for a host endpoint.
//
// A mapping bound to a specific host address matches only that address; one
// the runtime recorded with an empty or wildcard address matches any, which is
// how Docker records "-p 3000:3000".
func publishFor(r *Result, e Endpoint) (Publish, bool) {
	for _, p := range r.Publishes {
		if p.HostPort != e.Port || p.Protocol != transportOf(e.Protocol) {
			continue
		}
		switch p.HostAddress {
		case "", "0.0.0.0", "::":
			return p, true
		default:
			if p.HostAddress == e.Address {
				return p, true
			}
		}
	}
	return Publish{}, false
}

// withBackend fills in the container behind a forwarded endpoint, and records
// on that container's own service where it is published.
func withBackend(out model.Exposure, r *Result, containers []model.Container,
	forward Forward, containerID string, e Endpoint) model.Exposure {

	if out.Backend == nil {
		out.Backend = &model.Backend{
			Address: forward.BackendAddress,
			Port:    forward.BackendPort,
			Via:     forward.Via,
		}
	}
	out.Backend.Container = containerID

	matched := false
	for i := range containers {
		if containers[i].ID != containerID {
			continue
		}
		out.Image = containers[i].Image
		for j := range containers[i].Services {
			svc := &containers[i].Services[j]
			if !servesPort(svc, forward.BackendPort) {
				continue
			}
			out.Backend.Executable = svc.Executable
			out.Components = svc.Components
			out.Confidence = svc.Confidence
			out.Evidence = append(out.Evidence, fmt.Sprintf(
				"forwards to %s in container %s", svc.Executable, shortID(containerID)))
			svc.PublishedAs = model.SortedSet(append(svc.PublishedAs, e.String()))
			matched = true
		}
		break
	}
	if !matched {
		// The container is known but nothing in it was seen listening on the
		// port the forward names. Usually the process is unreadable, or it
		// exited between the two reads. Saying so beats an empty row, and
		// beats picking the container's only other listener and calling it
		// the answer.
		out.Evidence = append(out.Evidence, fmt.Sprintf(
			"container %s was identified, but no process in it was seen listening on port %d",
			shortID(containerID), forward.BackendPort))
	}
	if out.Confidence == "" {
		out.Confidence = model.ConfidenceLow
	}
	return out
}

// better reports whether a is the more informative row for the same socket.
//
// The daemon that will answer is a better statement than init holding the
// socket for it, and a row that names software beats one that does not.
func better(a, b model.Exposure) bool {
	if rank(a.Confidence) != rank(b.Confidence) {
		return rank(a.Confidence) > rank(b.Confidence)
	}
	return len(a.Components) > len(b.Components)
}

func rank(c model.Confidence) int {
	switch c {
	case model.ConfidenceHigh:
		return 3
	case model.ConfidenceMedium:
		return 2
	default:
		return 1
	}
}

// matchBackend finds the container a forward points at.
//
// The address is tried first, since it identifies the container exactly. The
// port alone is only accepted when exactly one container listens on it:
// several containers publishing 8080 is ordinary, and picking one of them
// would be a coin flip presented as a finding.
func matchBackend(r *Result, f Forward) *Container {
	ip := net.ParseIP(f.BackendAddress)
	for i := range r.Containers {
		for _, addr := range r.Containers[i].Addresses {
			if ip != nil && ip.Equal(net.ParseIP(addr)) {
				return &r.Containers[i]
			}
		}
	}

	var match *Container
	for i := range r.Containers {
		for _, s := range r.Containers[i].Services {
			for _, e := range s.Endpoints {
				if e.Port != f.BackendPort {
					continue
				}
				if match != nil && match.ID != r.Containers[i].ID {
					return nil // ambiguous
				}
				match = &r.Containers[i]
			}
		}
	}
	return match
}

// servesPort reports whether a container service listens on a port, ignoring
// the address: inside a container a daemon usually binds the wildcard, and the
// forward names the container's own address rather than that bind.
func servesPort(s *model.Service, port uint16) bool {
	want := fmt.Sprintf(":%d/", port)
	for _, e := range s.Endpoints {
		if strings.Contains(e, want) {
			return true
		}
	}
	return false
}

// shortID abbreviates a container id the way every runtime's own output does.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
