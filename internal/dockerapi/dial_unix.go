//go:build !windows

package dockerapi

import (
	"context"
	"net"
	"os"
	"time"
)

// endpoints are the Unix sockets a local engine listens on. Podman's
// user socket is included because it speaks the same API and a host running it
// is asking the same question.
func endpoints() []string {
	out := []string{"/var/run/docker.sock", "/run/docker.sock"}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		out = append(out, dir+"/podman/podman.sock", dir+"/docker.sock")
	}
	return out
}

// dialer connects to a Unix socket, if one is there at all.
func dialer(endpoint string) dialFunc {
	if fi, err := os.Stat(endpoint); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return nil
	}
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, "unix", endpoint)
	}
}
