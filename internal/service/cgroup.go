package service

import (
	"bufio"
	"io"
	"strings"
)

// UnitFromCgroup extracts the systemd unit and container id from a process's
// cgroup file.
//
// This is why swinv does not talk to D-Bus or shell out to systemctl: a single
// file read gives the owning unit, and it works for container scopes too. A
// line reads
//
//	0::/system.slice/nginx.service
//	0::/system.slice/docker-9d5a98d0dc04....scope
//
// on cgroup v2, or carries a controller list before the path on v1. The unit
// name is the last path segment that names one.
//
// A container id is returned separately because a service inside a container is
// a different statement from one on the host, and flattening the two loses the
// part an operator acts on.
func UnitFromCgroup(r io.Reader) (unit, container string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		// v2: "0::/path". v1: "12:pids:/path". The path is the last field.
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 3 {
			continue
		}
		path := fields[len(fields)-1]

		for _, segment := range strings.Split(path, "/") {
			switch {
			case strings.HasSuffix(segment, ".service"),
				strings.HasSuffix(segment, ".socket"),
				strings.HasSuffix(segment, ".mount"):
				if unit == "" {
					unit = segment
				}
			case strings.HasSuffix(segment, ".scope"):
				if id := containerID(segment); id != "" && container == "" {
					container = id
				} else if unit == "" {
					unit = segment
				}
			}
		}
		if unit != "" || container != "" {
			return unit, container
		}
	}
	return "", ""
}

// containerID pulls the identifier out of a container scope or slice segment.
//
// Runtimes name these differently -- "docker-<id>.scope", "crio-<id>.scope",
// "libpod-<id>.scope", and Kubernetes writes "cri-containerd-<id>.scope" -- so
// the prefix list is what has to be maintained, not a regular expression over
// hexadecimal.
func containerID(segment string) string {
	segment = strings.TrimSuffix(segment, ".scope")
	for _, prefix := range []string{
		"docker-", "crio-", "libpod-", "cri-containerd-", "containerd-",
	} {
		if strings.HasPrefix(segment, prefix) {
			return strings.TrimPrefix(segment, prefix)
		}
	}
	return ""
}
