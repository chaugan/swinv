package dockerapi

import (
	"context"
	"os"
	"testing"
	"time"
)

// A live check against whatever local engine is present. Skipped unless asked
// for, so it is a no-op in CI and on machines with no Docker.
func TestLiveEngine(t *testing.T) {
	if os.Getenv("SWINV_DOCKER_LIVE") == "" {
		t.Skip("set SWINV_DOCKER_LIVE=1 to run against the local engine")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c, err := Dial(ctx, 10*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Logf("endpoint: %s", c.Endpoint())

	containers, err := c.Containers(ctx)
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	t.Logf("%d containers", len(containers))
	for i, ctr := range containers {
		if i >= 6 {
			break
		}
		full, err := c.Inspect(ctx, ctr.ID)
		if err != nil {
			t.Errorf("Inspect(%s): %v", ctr.ID[:12], err)
			continue
		}
		t.Logf("%s  %-24s image=%-40s digest=%s", ctr.ID[:12], ctr.Name, ctr.Image, full.Digest)
		for _, p := range ctr.Ports {
			t.Logf("    published %s:%d -> %d/%s", p.HostIP, p.HostPort, p.ContainerPort, p.Protocol)
		}
		if len(full.Entrypoint) > 0 || len(full.Command) > 0 {
			t.Logf("    entrypoint=%v cmd=%v", full.Entrypoint, full.Command)
		}
	}
}
