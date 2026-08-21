//go:build linux

package service

import (
	"context"
	"os"
	"testing"
)

// TestCollectAgainstThisMachine runs the whole spine against real /proc.
//
// It asserts what is true regardless of what happens to be running, because a
// test that expects a particular daemon is a test that fails on a different
// machine. What it does check is the structure: endpoints are well formed,
// grouping is by process, and an unprivileged run degrades honestly rather
// than claiming nothing is listening.
func TestCollectAgainstThisMachine(t *testing.T) {
	res, err := Collect(context.Background(), "/proc")
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	t.Logf("%d services, %d sockets unattributed", len(res.Services), res.Unattributed)

	if len(res.Services) == 0 && res.Unattributed == 0 {
		t.Skip("nothing is listening here")
	}

	// Unprivileged, most sockets belong to other users and must be counted and
	// explained rather than silently dropped.
	if os.Geteuid() != 0 && res.Unattributed > 0 && len(res.Warnings) == 0 {
		t.Error("sockets went unattributed with no warning saying why")
	}

	seen := make(map[int]bool)
	for _, s := range res.Services {
		if seen[s.Process.PID] {
			t.Errorf("pid %d appears as two services; endpoints should group onto one", s.Process.PID)
		}
		seen[s.Process.PID] = true

		if len(s.Endpoints) == 0 {
			t.Errorf("pid %d is a service with no endpoints", s.Process.PID)
		}
		for _, e := range s.Endpoints {
			if e.Port == 0 {
				t.Errorf("pid %d has an endpoint on port 0: %+v", s.Process.PID, e)
			}
			if e.Address == "" {
				t.Errorf("pid %d has an endpoint with no address: %+v", s.Process.PID, e)
			}
			if e.Inode == 0 {
				t.Errorf("pid %d has an endpoint with no socket inode", s.Process.PID)
			}
		}
	}
}

func TestSocketInode(t *testing.T) {
	cases := map[string]uint64{
		"socket:[188093446]": 188093446,
		"socket:[1]":         1,
	}
	for in, want := range cases {
		got, ok := socketInode(in)
		if !ok || got != want {
			t.Errorf("socketInode(%q) = %d, %v; want %d, true", in, got, ok, want)
		}
	}
	for _, in := range []string{"/dev/null", "pipe:[123]", "socket:[]", "socket:[abc]", "", "anon_inode:[eventfd]"} {
		if _, ok := socketInode(in); ok {
			t.Errorf("socketInode(%q) reported a socket", in)
		}
	}
}

func TestUIDFromStatus(t *testing.T) {
	const status = "Name:\tnginx\nState:\tS (sleeping)\nUid:\t33\t33\t33\t33\nGid:\t33\t33\t33\t33\n"
	if got := uidFromStatus([]byte(status)); got != "33" {
		t.Errorf("uidFromStatus = %q, want 33 (the real uid, not the effective one)", got)
	}
	if got := uidFromStatus([]byte("Name:\tx\n")); got != "" {
		t.Errorf("uidFromStatus = %q, want empty when there is no Uid line", got)
	}
}
