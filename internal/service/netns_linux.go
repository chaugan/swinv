//go:build linux

package service

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// Namespace is one network namespace and the processes found in it.
type Namespace struct {
	// ID is the kernel's inode string, "net:[4026531833]".
	ID string

	// Host is true for the namespace init is in -- the one whose sockets are
	// reachable at this machine's addresses.
	Host bool

	// PIDs are the processes found in it, ascending. The first is used as the
	// representative for reading the namespace's socket tables.
	PIDs []int

	// Container is the container id, if the processes in this namespace share
	// one. A namespace can exist without a container: systemd's
	// PrivateNetwork=yes gives a unit its own, and this host has one.
	Container string
}

// namespaces groups every visible process by its network namespace.
//
// This is what makes "exposed from the host" a fact rather than a guess. A
// process bound to 0.0.0.0 inside a container's namespace is not reachable at
// this machine's addresses, and the only way to tell that from a host bind is
// to know which namespace the socket was read from. Comparing against init's
// namespace is exact and needs no runtime knowledge at all.
//
// Reading another process's namespace link needs root. Unprivileged, the links
// are unreadable and everything collapses to the scan's own namespace, which
// is reported as a blind spot rather than as an empty result.
func namespaces(procRoot string) ([]Namespace, error) {
	hostNS, err := os.Readlink(filepath.Join(procRoot, "1", "ns", "net"))
	if err != nil {
		// Without an anchor there is no honest way to call anything "the
		// host", so treat the scan's own namespace as it. That is true when
		// swinv runs on the host, which is the supported case.
		hostNS, _ = os.Readlink(filepath.Join(procRoot, "self", "ns", "net"))
	}

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}

	byID := make(map[string]*Namespace)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		id, err := os.Readlink(filepath.Join(procRoot, e.Name(), "ns", "net"))
		if err != nil || id == "" {
			continue
		}
		ns, ok := byID[id]
		if !ok {
			ns = &Namespace{ID: id, Host: id == hostNS}
			byID[id] = ns
		}
		ns.PIDs = append(ns.PIDs, pid)
	}

	out := make([]Namespace, 0, len(byID))
	for _, ns := range byID {
		sort.Ints(ns.PIDs)
		// The host namespace never carries a container id, even though it
		// contains containerised processes: a --network=host container shares
		// it, and taking that container's id as the namespace's would stamp it
		// onto every ordinary host process -- which reported docker-proxy, and
		// everything else on the machine, as running inside somebody's
		// container.
		if ns.Host {
			out = append(out, *ns)
			continue
		}
		// Otherwise the id comes from the processes in the namespace, not from
		// its existence: a namespace with no container id is ordinary
		// (PrivateNetwork=yes), not an error.
		for _, pid := range ns.PIDs {
			if f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup")); err == nil {
				_, container := UnitFromCgroup(f)
				_ = f.Close()
				if container != "" {
					ns.Container = container
					break
				}
			}
		}
		out = append(out, *ns)
	}
	// Host first, then by id, so output order does not depend on directory
	// iteration.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// localAddresses reads the IPv4 addresses assigned inside a namespace, from
// the representative process's fib_trie.
//
// This is the join key for a published port: a forwarding process's command
// line names the address it forwards to, and that address belongs to one of
// these namespaces. There is no stable /proc file for it -- fib_trie is debug
// output -- so a failure here degrades the backend to a port-only match rather
// than failing the scan.
func localAddresses(procRoot string, pid int) []string {
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "net", "fib_trie"))
	if err != nil {
		return nil
	}
	return parseFibTrieLocal(string(raw))
}
