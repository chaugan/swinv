//go:build windows

package dockerapi

import (
	"context"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

// endpoints are the named pipes a local engine listens on, in the order they
// are tried. Docker Desktop uses the first; the second is what a Windows
// container host with a native daemon uses.
func endpoints() []string {
	return []string{
		`\\.\pipe\docker_engine`,
		`\\.\pipe\dockerDesktopLinuxEngine`,
	}
}

// dialer connects to a named pipe.
//
// A short dial timeout on purpose: the pipe either exists and answers at once,
// or it does not exist and the inventory should carry on. Waiting on a
// half-present Docker installation is not worth a minute of a scan.
func dialer(endpoint string) dialFunc {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		timeout := 2 * time.Second
		return winio.DialPipe(endpoint, &timeout)
	}
}
