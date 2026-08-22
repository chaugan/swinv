package service

import (
	"path"
	"strconv"
	"strings"
)

// Forward is a host endpoint that leads somewhere else.
type Forward struct {
	HostAddress    string
	HostPort       uint16
	Protocol       string
	BackendAddress string
	BackendPort    uint16
	Via            string
}

// forwarders are the executables known to hold a host socket on behalf of
// something else. Recognising one is what stops a published container port
// being attributed to the package that ships the proxy -- reporting
// "docker-ce" as the software behind port 3000 is true and useless, and it was
// 14 of 31 services on the development host.
//
// The list is used to *withhold* an attribution, which is safe when it is
// wrong in either direction: an unrecognised forwarder is attributed to its own
// package, exactly as before, and a misrecognised one loses an attribution it
// should not have had much confidence in anyway.
var forwarders = map[string]string{
	"docker-proxy":             "docker",
	"rootlessport":             "docker-rootless",
	"rootlesskit-docker-proxy": "docker-rootless",
	"slirp4netns":              "podman",
	"pasta":                    "podman",
	"pasta.avx2":               "podman",
}

// IsForwarder reports whether an executable holds host sockets on behalf of
// another workload, and names the runtime it belongs to.
func IsForwarder(exe string) (runtime string, ok bool) {
	if exe == "" {
		return "", false
	}
	runtime, ok = forwarders[path.Base(exe)]
	return runtime, ok
}

// ParseDockerProxy reads a docker-proxy command line.
//
// This is enrichment and never discovery. docker-proxy does not exist at all
// when the daemon runs with "userland-proxy": false, which CIS recommends, nor
// under rootful Podman's default netavark, and in those configurations
// publishing is pure netfilter DNAT with no process and no socket. Its absence
// therefore means nothing, and nothing may be concluded from it -- which is
// why the blind spots are reported as data rather than inferred here.
//
// The argv is:
//
//	docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 3000 \
//	             -container-ip 172.17.0.2 -container-port 3000 -use-listen-fd
func ParseDockerProxy(command string) (Forward, bool) {
	fields := strings.Fields(command)
	f := Forward{Via: "docker-proxy-argv", Protocol: "tcp"}

	var haveHost, haveBackend bool
	for i := 0; i+1 < len(fields); i++ {
		value := fields[i+1]
		switch fields[i] {
		case "-proto", "--proto":
			f.Protocol = value
		case "-host-ip", "--host-ip":
			f.HostAddress = value
		case "-host-port", "--host-port":
			if p, err := strconv.ParseUint(value, 10, 16); err == nil {
				f.HostPort = uint16(p)
				haveHost = true
			}
		case "-container-ip", "--container-ip":
			f.BackendAddress = value
		case "-container-port", "--container-port":
			if p, err := strconv.ParseUint(value, 10, 16); err == nil {
				f.BackendPort = uint16(p)
				haveBackend = true
			}
		}
	}
	if !haveHost || !haveBackend || f.BackendAddress == "" {
		return Forward{}, false
	}
	return f, true
}
