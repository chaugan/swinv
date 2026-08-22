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
//	0::/docker/9d5a98d0dc04...
//	0::/kubepods/burstable/pod<uid>/9d5a98d0dc04...
//
// on cgroup v2, or carries a controller list before the path on v1. The last
// two are the cgroupfs driver, which writes no ".scope" at all.
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
			if id := containerID(segment); id != "" {
				if container == "" {
					container = id
				}
				continue
			}
			switch {
			case strings.HasSuffix(segment, ".service"),
				strings.HasSuffix(segment, ".socket"),
				strings.HasSuffix(segment, ".mount"):
				// The last one, not the first. A user session daemon sits at
				// /user.slice/user-1000.slice/user@1000.service/app.slice/foo.service,
				// where the first match is the session manager and the last is
				// the thing actually running.
				unit = segment
			case strings.HasSuffix(segment, ".scope"):
				if unit == "" {
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

// containerID pulls the identifier out of a cgroup path segment.
//
// Matching is on the *shape* of the segment rather than on a list of runtime
// prefixes, because the prefix list only ever described the systemd cgroup
// driver. With the cgroupfs driver the same container is "/docker/<64hex>" or
// "/kubepods/.../<64hex>" with no ".scope" anywhere, and a prefix list silently
// reported those processes as running on the host -- which then matched their
// executables against the host's package databases and produced the wrong
// package, at the wrong version, with the highest confidence.
//
// A bare 64-hex segment is the common form; runtimes also prefix it
// ("docker-", "crio-", "libpod-", "cri-containerd-") and systemd appends
// ".scope". Some runtimes use a 32-hex id, and LXC uses a plain name under
// /lxc/, which is handled by the caller's path context rather than here.
func containerID(segment string) string {
	segment = strings.TrimSuffix(segment, ".scope")
	// A runtime prefix is itself the proof that the segment names a container,
	// so the identifier after it only has to look like one.
	for _, prefix := range []string{
		"cri-containerd-", "docker-", "crio-", "libpod-", "containerd-", "conmon-",
	} {
		if rest, ok := strings.CutPrefix(segment, prefix); ok {
			if isHex(rest) && len(rest) >= shortIDLen {
				return rest
			}
		}
	}
	// Without a prefix there is nothing but the shape to go on, so it has to be
	// the full length a runtime actually writes. Accepting anything shorter
	// would claim that an ordinary cgroup named "cafe1234" is a container.
	if len(segment) == 64 || len(segment) == 32 {
		if isHex(segment) {
			return segment
		}
	}
	return ""
}

// shortIDLen is the shortest identifier accepted after a runtime prefix. Docker
// abbreviates to twelve characters in its own output, so that is the floor.
const shortIDLen = 12

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
