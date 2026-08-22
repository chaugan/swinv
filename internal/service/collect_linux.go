//go:build linux

package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// collect reports what is listening on this machine.
//
// Unprivileged, this degrades rather than fails: /proc/net is world-readable,
// so the endpoints are found, but /proc/<pid>/fd belongs to the process owner,
// so the socket cannot be attributed to a process it does not own -- which on a
// server is nearly all of them. The endpoint is still reported, with no process
// against it, because "something is listening on 443 and I could not see what"
// is a more useful statement than silence.
func collect(ctx context.Context, procRoot string) (*Result, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}

	spaces, err := namespaces(procRoot)
	if err != nil {
		return nil, err
	}

	// Every namespace's sockets are read up front, and each endpoint is tagged
	// with the namespace it came from. Socket inodes come from a single global
	// sockfs superblock, so they stay unique across namespaces and the one
	// expensive pass over /proc/<pid>/fd still resolves all of them at once.
	var (
		endpoints []Endpoint
		warnings  []string
		nsByID    = make(map[string]Namespace, len(spaces))
	)
	for _, ns := range spaces {
		nsByID[ns.ID] = ns
		if len(ns.PIDs) == 0 {
			continue
		}
		read, w := readAllTables(procRoot, ns.PIDs[0])
		warnings = append(warnings, w...)
		for i := range read {
			read[i].NetNS = ns.ID
		}
		endpoints = append(endpoints, read...)
	}
	if len(endpoints) == 0 {
		return &Result{Warnings: warnings}, nil
	}

	owners, unattributed, err := mapSocketsToProcesses(ctx, procRoot, endpoints)
	if err != nil {
		return nil, err
	}
	if unattributed > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"%d of %d listening sockets could not be attributed to a process; "+
				"reading another user's open files needs root, so an unprivileged scan "+
				"sees only its own", unattributed, len(endpoints)))
	}

	services := groupByProcess(owners, nsByID)
	sort.Slice(services, func(i, j int) bool {
		if services[i].Process.PID != services[j].Process.PID {
			return services[i].Process.PID < services[j].Process.PID
		}
		return services[i].Process.Exe < services[j].Process.Exe
	})

	host, containers := split(procRoot, services, nsByID)
	return &Result{
		Services:     host,
		Containers:   containers,
		Warnings:     warnings,
		Unattributed: unattributed,
	}, nil
}

// split separates the host namespace's listeners from the containerised ones.
//
// The separation is the product. A container's listeners must not join the
// host list, because every consumer of that list reads it as "reachable on
// this machine" -- and a container port is reachable only if something
// published it, which is a separate fact recorded separately.
func split(procRoot string, services []Service, nsByID map[string]Namespace) ([]Service, []Container) {
	var host []Service
	byContainer := make(map[string]*Container)
	var order []string

	for _, s := range services {
		if s.HostNetwork {
			host = append(host, s)
			continue
		}
		ns := nsByID[s.NetNS]
		id := ns.Container
		if id == "" {
			// A namespace with no container: systemd's PrivateNetwork=yes
			// gives a unit its own, and nothing in it is reachable from
			// anywhere. Keyed on the namespace so it is still grouped, but it
			// is not called a container.
			id = s.NetNS
		}
		c, ok := byContainer[id]
		if !ok {
			c = &Container{ID: ns.Container, RootPID: s.Process.PID}
			if ns.Container != "" {
				c.Addresses = localAddresses(procRoot, s.Process.PID)
			}
			byContainer[id] = c
			order = append(order, id)
		}
		c.Services = append(c.Services, s)
	}

	out := make([]Container, 0, len(order))
	for _, id := range order {
		if byContainer[id].ID == "" {
			// Not a container, and nothing published can point at it. Dropped
			// rather than reported as one.
			continue
		}
		out = append(out, *byContainer[id])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return host, out
}

// readAllTables reads one namespace's four socket tables, through a process
// known to be in it. A missing table is not fatal: a host with IPv6 disabled
// has no tcp6, and a container may have none at all.
func readAllTables(procRoot string, pid int) ([]Endpoint, []string) {
	var (
		all      []Endpoint
		warnings []string
	)
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	for _, t := range []struct {
		file  string
		proto Protocol
	}{
		{"net/tcp", TCP}, {"net/tcp6", TCP6},
		{"net/udp", UDP}, {"net/udp6", UDP6},
	} {
		f, err := os.Open(filepath.Join(base, t.file))
		if err != nil {
			continue
		}
		endpoints, err := ParseNetTable(f, t.proto)
		// Read-only; nothing it could report affects what was already parsed.
		_ = f.Close()
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		all = append(all, endpoints...)
	}
	return all, warnings
}

// socketOwner is one endpoint and the process holding it.
type socketOwner struct {
	endpoint Endpoint
	process  Process
}

// mapSocketsToProcesses walks /proc/<pid>/fd looking for the socket inodes.
//
// One pass over every process, rather than one pass per socket: a busy host has
// tens of thousands of file descriptors and a few dozen listeners, so the walk
// is the expensive part and doing it once matters.
func mapSocketsToProcesses(ctx context.Context, procRoot string, endpoints []Endpoint) ([]socketOwner, int, error) {
	wanted := make(map[uint64]Endpoint, len(endpoints))
	for _, e := range endpoints {
		wanted[e.Inode] = e
	}

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, 0, fmt.Errorf("service: reading %s: %w", procRoot, err)
	}

	var owners []socketOwner
	found := make(map[uint64]bool, len(wanted))

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}

		inodes := socketInodes(filepath.Join(procRoot, entry.Name(), "fd"), wanted)
		if len(inodes) == 0 {
			continue
		}

		p := readProcess(procRoot, pid)
		for _, inode := range inodes {
			owners = append(owners, socketOwner{endpoint: wanted[inode], process: p})
			found[inode] = true
		}
	}
	return owners, len(wanted) - len(found), nil
}

// socketInodes returns which of the wanted socket inodes this process holds.
//
// An unreadable fd directory is silent: it belongs to another user, which is
// the ordinary case for an unprivileged scan and is counted once at the end
// rather than warned about per process.
func socketInodes(fdDir string, wanted map[uint64]Endpoint) []uint64 {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}

	var out []uint64
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		inode, ok := socketInode(target)
		if !ok {
			continue
		}
		if _, want := wanted[inode]; want {
			out = append(out, inode)
		}
	}
	return out
}

// socketInode parses a "socket:[12345]" fd symlink target.
func socketInode(target string) (uint64, bool) {
	const prefix, suffix = "socket:[", "]"
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, suffix) {
		return 0, false
	}
	n, err := strconv.ParseUint(target[len(prefix):len(target)-len(suffix)], 10, 64)
	return n, err == nil
}

// groupByProcess collapses endpoints onto the process serving them.
//
// One process routinely holds several: a web server binds v4 and v6, and often
// both 80 and 443. Reporting four services where there is one would misstate
// how much is running.
func groupByProcess(owners []socketOwner, nsByID map[string]Namespace) []Service {
	byPID := make(map[int]*Service)
	var order []int

	for _, o := range owners {
		s, ok := byPID[o.process.PID]
		if !ok {
			ns := nsByID[o.endpoint.NetNS]
			s = &Service{
				Process:     o.process,
				NetNS:       o.endpoint.NetNS,
				HostNetwork: ns.Host,
			}
			// A --network=host container, or a hostNetwork pod: the process is
			// containerised but its sockets are the host's. Both facts are
			// true and both are kept.
			if s.Process.Container == "" && ns.Container != "" {
				s.Process.Container = ns.Container
			}
			byPID[o.process.PID] = s
			order = append(order, o.process.PID)
		}
		s.Endpoints = append(s.Endpoints, o.endpoint)
	}

	out := make([]Service, 0, len(order))
	for _, pid := range order {
		s := byPID[pid]
		s.SocketActivated = isInit(s.Process)
		sort.Slice(s.Endpoints, func(i, j int) bool {
			if s.Endpoints[i].Port != s.Endpoints[j].Port {
				return s.Endpoints[i].Port < s.Endpoints[j].Port
			}
			return s.Endpoints[i].Protocol < s.Endpoints[j].Protocol
		})
		out = append(out, *s)
	}
	return out
}

// isInit reports whether a process is pid 1, which on a systemd host means the
// socket is activated rather than held by the service that will answer on it.
func isInit(p Process) bool {
	return p.PID == 1 && (strings.HasSuffix(p.Exe, "/systemd") || strings.HasSuffix(p.Exe, "/init"))
}
