package service

import (
	"os"
	"path/filepath"
	"testing"
)

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// Two entries are properties of the approach and must never be conditional:
// they are what stops any row being read as a reachability claim.
func TestBlindSpotsAlwaysNameTheApproachsLimits(t *testing.T) {
	got := DetectBlindSpots(t.TempDir(), true)
	for _, want := range []string{BlindNetfilter, BlindFirewall} {
		if !has(got, want) {
			t.Errorf("%q missing from %v", want, got)
		}
	}
	if has(got, BlindUnprivileged) {
		t.Errorf("an elevated scan reported %q", BlindUnprivileged)
	}
}

func TestBlindSpotsUnprivileged(t *testing.T) {
	if got := DetectBlindSpots(t.TempDir(), false); !has(got, BlindUnprivileged) {
		t.Errorf("unprivileged scan did not report it: %v", got)
	}
}

// A Kubernetes node reporting six endpoints is not a small attack surface, it
// is a partially observed one, and the output has to say so.
func TestBlindSpotsKubernetesNode(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var", "lib", "kubelet"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := DetectBlindSpots(root, true); !has(got, BlindKubernetes) {
		t.Errorf("kubelet state present but %q missing: %v", BlindKubernetes, got)
	}
}

// With userland-proxy disabled every published port is a netfilter rule and no
// process holds one, so the host would otherwise look like it publishes
// nothing.
func TestBlindSpotsDockerUserlandProxyDisabled(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc", "docker")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(dir, "daemon.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write(`{"userland-proxy": false}`)
	if got := DetectBlindSpots(root, true); !has(got, BlindDockerNoProxy) {
		t.Errorf("userland-proxy disabled but %q missing: %v", BlindDockerNoProxy, got)
	}

	// The default, and a malformed file, must not raise a blind spot that is
	// not there: a false one is as misleading as a missing one.
	for _, body := range []string{`{"userland-proxy": true}`, `{}`, `not json`} {
		write(body)
		if got := DetectBlindSpots(root, true); has(got, BlindDockerNoProxy) {
			t.Errorf("daemon.json %q produced %q", body, BlindDockerNoProxy)
		}
	}
}
