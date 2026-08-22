package service

import (
	"context"
	"sort"
)

// Process is the process holding a listening socket.
type Process struct {
	PID int

	// Exe is the path to the executable, as it exists in *that process's*
	// mount namespace. For a containerised process this is a path that need
	// not exist on the host, and joining it against host components without
	// resolving through /proc/<pid>/root attributes the container's service to
	// whatever the host happens to have at the same path.
	Exe string

	// Command is the process's argv, joined by spaces.
	//
	// It matters most where Exe is least useful: an interpreter. For java,
	// python or node the executable identifies the runtime and says nothing
	// about the product, and the command line is where the application is
	// named.
	Command string

	// Unit is the owning systemd unit, from the process's cgroup. The single
	// most useful label a service can carry, and one file read to obtain.
	Unit string

	// Container is the container id when the process runs in one. A service
	// inside a container is a different statement from one on the host.
	Container string

	// User is the numeric uid the process runs as.
	User string

	// Isolated is true when the process does not share init's mount namespace,
	// so Exe names a file in some other filesystem than this host's.
	//
	// This is the guard that does not depend on recognising anything. Deciding
	// isolation from the cgroup means keeping up with every runtime's layout,
	// and the first version of that list only covered the systemd cgroup
	// driver -- so a container under the cgroupfs driver looked like a host
	// process and had its executable matched against the host's package
	// databases, yielding the wrong package at the wrong version with the
	// highest confidence. Comparing /proc/<pid>/ns/mnt against /proc/1/ns/mnt
	// is one readlink, is true by construction, and also catches
	// systemd-nspawn, RootDirectory=/RootImage= units, and snap confinement,
	// none of which are containers in the cgroup sense.
	Isolated bool
}

// Service is one process and everything it is listening on.
type Service struct {
	Process   Process
	Endpoints []Endpoint

	// SocketActivated is true when init holds the socket rather than the
	// service itself.
	//
	// Following socket to process then lands on systemd, which is true and
	// useless: on a stock host that is how port 22 is reported, and the
	// operator wants "ssh". The service may also not be running at all yet,
	// since the point of activation is to start it on first connection -- so
	// this is a genuinely different state from a daemon holding its own
	// socket, not a failure to resolve one.
	SocketActivated bool
}

// Result is what a scan of the machine's listening sockets produced.
type Result struct {
	Services []Service

	// Unattributed counts listening sockets whose owning process could not be
	// identified, which unprivileged means nearly all of them.
	Unattributed int

	Warnings []string
}

// Collect reports what is listening. Implemented on Linux; elsewhere it
// returns nothing rather than an error, since a caller asking on a platform
// without /proc has not done anything wrong.
func Collect(ctx context.Context, procRoot string) (*Result, error) {
	return collect(ctx, procRoot)
}

// ExePaths returns the distinct executable paths of the collected services, in
// sorted order, for use as an ownership probe against the package databases.
//
// Processes in another mount namespace are left out. Their executable path is
// a path in that namespace, so asking the host's package databases about it
// invites exactly the false match the attribution refuses to make.
func (r *Result) ExePaths() []string {
	if r == nil {
		return nil
	}
	seen := make(map[string]bool, len(r.Services))
	var out []string
	for _, s := range r.Services {
		if s.Process.Exe == "" || s.Process.Isolated || s.SocketActivated {
			continue
		}
		if seen[s.Process.Exe] {
			continue
		}
		seen[s.Process.Exe] = true
		out = append(out, s.Process.Exe)
	}
	sort.Strings(out)
	return out
}
