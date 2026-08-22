//go:build windows

package service

import (
	"context"
	"time"

	"github.com/chaugan/swinv/internal/dockerapi"
	"github.com/chaugan/swinv/internal/model"
)

// dockerTimeout bounds the whole conversation with the engine. It is a local
// pipe, so it either answers promptly or it is not worth waiting for during an
// inventory scan.
const dockerTimeout = 15 * time.Second

// EnrichContainers has no direct route on Windows.
//
// A Docker Desktop container is a Linux process inside a WSL2 virtual
// machine: it has no entry in the Windows process table and no
// /proc/<pid>/root to read. Everything about it therefore comes from the
// runtime, which RuntimeContainers does for both platforms -- so there is
// nothing platform-specific left to do here.
func EnrichContainers(string, []Container, bool) []model.Container { return nil }

// DockerPublishes asks the engine which host ports it forwards into
// containers.
//
// The engine stating its own mapping beats anything derivable from a
// forwarding process's command line, and on Windows it is the only source: the
// proxy holding the port is all a Windows API can see.
func DockerPublishes() []Publish {
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()

	client, err := dockerapi.Dial(ctx, dockerTimeout)
	if err != nil {
		return nil
	}
	listed, err := client.Containers(ctx, false)
	if err != nil {
		return nil
	}

	var out []Publish
	for _, c := range listed {
		for _, p := range c.Ports {
			out = append(out, Publish{
				HostAddress:   p.HostIP,
				HostPort:      p.HostPort,
				Protocol:      p.Protocol,
				ContainerID:   c.ID,
				ContainerPort: p.ContainerPort,
				Via:           "docker-engine-api",
			})
		}
	}
	return out
}
