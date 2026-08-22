package service

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Blind spot identifiers. Machine-readable rather than prose, because a
// consumer's ingest pipeline drops warning strings and these are the only
// thing that distinguishes "swinv looked and found nothing exposed" from
// "swinv could not look".
const (
	// BlindNetfilter is always present on Linux. A port published by a DNAT
	// rule with no process behind it -- Kubernetes NodePort in iptables or
	// IPVS mode, Docker with userland-proxy disabled, rootful Podman's default
	// netavark, any hand-written rule -- has no listening socket, and there is
	// no /proc interface that would reveal one.
	BlindNetfilter = "netfilter-dnat-not-read"

	// BlindFirewall is always present. Nothing here reads a firewall, so no
	// row in the report is a statement about reachability.
	BlindFirewall = "firewall-rules-not-read"

	// BlindUnprivileged: another process's open files and namespace links are
	// unreadable, so most sockets cannot be attributed and container
	// namespaces cannot be enumerated.
	BlindUnprivileged = "process-owners-not-readable-unprivileged"

	// BlindKubernetes: this machine looks like a Kubernetes node, where the
	// bulk of published ports are NodePort rules and therefore invisible. A
	// node reporting six endpoints is not a small attack surface, it is a
	// partially observed one.
	BlindKubernetes = "kubernetes-node-nodeport-not-observable"

	// BlindContainerFilesystem: containers are running, but their filesystems
	// are not reachable, so the packages inside them could not be read. This
	// is the normal state on Windows, where a Docker Desktop container is a
	// Linux process inside a virtual machine. The workload and its image are
	// still named; what is missing is the package identity a vulnerability
	// matcher can use.
	BlindContainerFilesystem = "container-packages-not-readable"

	// BlindDockerNoProxy: the Docker daemon is configured with
	// "userland-proxy": false, so published ports are netfilter rules and no
	// process holds them. Without this the host is indistinguishable from one
	// publishing nothing.
	BlindDockerNoProxy = "docker-userland-proxy-disabled"
)

// DetectBlindSpots reports what this scan could not observe.
//
// Two entries are unconditional: they are properties of the approach, not of
// the machine. The rest are file-existence and configuration checks, which is
// all this tool does anywhere.
func DetectBlindSpots(root string, elevated bool) []string {
	out := []string{BlindNetfilter, BlindFirewall}
	if !elevated {
		out = append(out, BlindUnprivileged)
	}
	if isKubernetesNode(root) {
		out = append(out, BlindKubernetes)
	}
	if dockerUserlandProxyDisabled(root) {
		out = append(out, BlindDockerNoProxy)
	}
	return out
}

// isKubernetesNode reports whether the kubelet's state is present.
//
// Presence of the directory, not a running process: a node whose kubelet is
// momentarily down is still a node whose ports this scan cannot see.
func isKubernetesNode(root string) bool {
	for _, p := range []string{
		"var/lib/kubelet",
		"etc/kubernetes/kubelet.conf",
		"run/containerd/io.containerd.runtime.v2.task/k8s.io",
	} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			return true
		}
	}
	return false
}

// dockerUserlandProxyDisabled reads the daemon configuration for the setting
// that removes docker-proxy entirely.
//
// Worth one file read: with it set, every published port on the machine is a
// netfilter rule this scan cannot see, and the report would otherwise look
// like a host with nothing published.
func dockerUserlandProxyDisabled(root string) bool {
	raw, err := os.ReadFile(filepath.Join(root, "etc", "docker", "daemon.json"))
	if err != nil {
		return false
	}
	var cfg struct {
		UserlandProxy *bool `json:"userland-proxy"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return false
	}
	return cfg.UserlandProxy != nil && !*cfg.UserlandProxy
}
