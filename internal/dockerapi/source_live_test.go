package dockerapi

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Reads a real container's filesystem through the runtime, running or not.
// Skipped unless asked for.
func TestLiveContainerSource(t *testing.T) {
	if os.Getenv("SWINV_DOCKER_LIVE") == "" {
		t.Skip("set SWINV_DOCKER_LIVE=1 to run against the local engine")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c, err := Dial(ctx, 20*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	all, err := c.Containers(ctx, true)
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}

	var running, stopped int
	for _, ctr := range all {
		src := c.Source(ctx, ctr.ID)

		// os-release is a symlink on Debian, so this also proves the chain is
		// followed rather than stopping at the link.
		raw, err := src.ReadFile("/etc/os-release")
		state := ctr.State
		if err != nil {
			t.Logf("%s  %-24s state=%-8s no os-release: %v", ctr.ID[:12], ctr.Name, state, err)
			continue
		}
		id := ""
		for _, line := range strings.Split(string(raw), "\n") {
			if v, ok := strings.CutPrefix(line, "ID="); ok {
				id = strings.Trim(v, `"`)
			}
		}
		t.Logf("%s  %-24s state=%-8s os=%s", ctr.ID[:12], ctr.Name, state, id)
		if state == "running" {
			running++
		} else {
			stopped++
		}
	}
	t.Logf("read the filesystem of %d running and %d stopped container(s)", running, stopped)
	if stopped == 0 {
		t.Log("note: no stopped containers present, so that path was not exercised")
	}
}
