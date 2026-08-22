//go:build linux

package service

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeProc builds a /proc tree. Namespace links are symlinks whose *target* is
// the kernel's "net:[...]" string; the target need not exist, which is what
// makes this testable without root or real namespaces.
func fakeProc(t *testing.T, procs map[int]struct{ netns, cgroup string }) string {
	t.Helper()
	root := t.TempDir()
	for pid, p := range procs {
		dir := filepath.Join(root, itoa(pid))
		if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p.netns, filepath.Join(dir, "ns", "net")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(p.cgroup), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestNamespaces(t *testing.T) {
	const (
		hostNS = "net:[4026531833]"
		ctrNS  = "net:[4026532711]"
		privNS = "net:[4026532432]"
		ctrID  = "df613448bf6ab0fbd2050e042709453eb7765fe5d035a32addb74fd8ef710c6a"
	)
	root := fakeProc(t, map[int]struct{ netns, cgroup string }{
		1:   {hostNS, "0::/init.scope\n"},
		811: {hostNS, "0::/system.slice/ssh.service\n"},
		// A --network=host container: it shares init's namespace, and its id
		// must not become the namespace's or it would be stamped on every
		// host process.
		900:  {hostNS, "0::/system.slice/docker-aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888.scope\n"},
		1006: {ctrNS, "0::/system.slice/docker-" + ctrID + ".scope\n"},
		1007: {ctrNS, "0::/system.slice/docker-" + ctrID + ".scope\n"},
		2255: {privNS, "0::/system.slice/polkit.service\n"},
	})

	got, err := namespaces(root)
	if err != nil {
		t.Fatalf("namespaces: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d namespaces, want 3: %+v", len(got), got)
	}

	// Host first, and carrying no container id despite holding one.
	if !got[0].Host || got[0].ID != hostNS {
		t.Fatalf("first namespace = %+v, want the host's", got[0])
	}
	if got[0].Container != "" {
		t.Errorf("the host namespace claims container %q; that id would be stamped "+
			"on every ordinary host process", got[0].Container)
	}
	if len(got[0].PIDs) != 3 || got[0].PIDs[0] != 1 {
		t.Errorf("host pids = %v", got[0].PIDs)
	}

	byID := map[string]Namespace{}
	for _, ns := range got[1:] {
		if ns.Host {
			t.Errorf("namespace %s claims to be the host's", ns.ID)
		}
		byID[ns.ID] = ns
	}
	if byID[ctrNS].Container != ctrID {
		t.Errorf("container namespace id = %q, want %q", byID[ctrNS].Container, ctrID)
	}
	// PrivateNetwork=yes gives a unit its own namespace. It is not a
	// container, and calling it one would invent a workload.
	if byID[privNS].Container != "" {
		t.Errorf("a PrivateNetwork unit was reported as container %q", byID[privNS].Container)
	}
}

// With no readable init link there is no honest anchor, and the scan's own
// namespace stands in. It must still produce a result rather than an error.
func TestNamespacesWithoutInit(t *testing.T) {
	root := fakeProc(t, map[int]struct{ netns, cgroup string }{
		811: {"net:[4026531833]", "0::/system.slice/ssh.service\n"},
	})
	got, err := namespaces(root)
	if err != nil {
		t.Fatalf("namespaces: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d namespaces", len(got))
	}
}
