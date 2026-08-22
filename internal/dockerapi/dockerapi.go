// Package dockerapi reads container state from a local Docker Engine.
//
// This is the one place swinv talks to a daemon, and it is here because on
// Windows there is no alternative. Docker Desktop runs Linux containers inside
// a WSL2 virtual machine: their processes are not Windows processes, they have
// no entry in the Windows process table, and their listening sockets live in
// network namespaces inside that VM. No Windows API reaches them. What Windows
// *can* see is Docker's proxy holding the published port — which is exactly
// the "docker-ce owns port 3000" non-answer the Linux collector exists to
// avoid, and on Windows it cannot be followed any other way.
//
// It remains true that swinv performs no network activity: this is a local
// named pipe (Windows) or Unix socket (Linux), kernel IPC with no address and
// no route. Nothing here reaches a registry or any other host.
//
// Everything is best-effort. A machine with no Docker, a daemon that is not
// running, or a user outside the docker group produces no containers and no
// error — the inventory is not worth failing over a section that could not be
// collected, and the caller records a blind spot instead.
package dockerapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// apiVersion is pinned low deliberately. The endpoints used here have been
// stable for years, and asking for an old version means a newer daemon still
// answers rather than refusing a version it has never heard of.
const apiVersion = "v1.41"

// maxResponseBytes caps every response body. The daemon is local and trusted
// to a point, but an inventory collector should not be the thing that runs a
// machine out of memory because a container list was enormous.
const maxResponseBytes = 64 << 20

// Client talks to a local Docker Engine.
type Client struct {
	http *http.Client
	// endpoint is recorded for evidence: which socket answered matters when
	// several runtimes are installed.
	endpoint string
}

// Container is what the daemon says about one container.
type Container struct {
	ID      string
	Name    string
	Image   string
	ImageID string
	// Digest is the registry manifest digest where the daemon knows one. A
	// locally built image that was never pushed has none.
	Digest string
	State  string

	// Ports are the published mappings, straight from the daemon. This is the
	// whole reason to ask: it says which host port reaches which container
	// port, exactly, with no argv to parse and no address to guess.
	Ports []PortMapping

	// Entrypoint and Command are what the container was told to run, which is
	// the only description of the workload available without entering it.
	Entrypoint []string
	Command    []string

	Labels map[string]string
}

// PortMapping is one published port.
type PortMapping struct {
	HostIP        string
	HostPort      uint16
	ContainerPort uint16
	Protocol      string
}

// PodName returns the Kubernetes pod this container belongs to, when the
// labels say so. Never inferred.
func (c Container) PodName() (name, namespace string, ok bool) {
	name = c.Labels["io.kubernetes.pod.name"]
	namespace = c.Labels["io.kubernetes.pod.namespace"]
	return name, namespace, name != ""
}

// Dial connects to a local Docker Engine, or reports that there is none.
func Dial(ctx context.Context, timeout time.Duration) (*Client, error) {
	for _, endpoint := range endpoints() {
		dial := dialer(endpoint)
		if dial == nil {
			continue
		}
		c := &Client{
			endpoint: endpoint,
			http: &http.Client{
				Timeout:   timeout,
				Transport: &http.Transport{DialContext: dial},
			},
		}
		// A ping, so that "there is a socket" and "there is a daemon behind
		// it" stay distinguishable.
		if err := c.get(ctx, "/_ping", nil); err == nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no local Docker Engine answered")
}

// Endpoint reports which socket answered.
func (c *Client) Endpoint() string { return c.endpoint }

// Containers lists the running containers.
func (c *Client) Containers(ctx context.Context) ([]Container, error) {
	var raw []struct {
		ID      string            `json:"Id"`
		Names   []string          `json:"Names"`
		Image   string            `json:"Image"`
		ImageID string            `json:"ImageID"`
		State   string            `json:"State"`
		Labels  map[string]string `json:"Labels"`
		Ports   []struct {
			IP          string `json:"IP"`
			PrivatePort uint16 `json:"PrivatePort"`
			PublicPort  uint16 `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
	}
	if err := c.get(ctx, "/containers/json", &raw); err != nil {
		return nil, err
	}

	out := make([]Container, 0, len(raw))
	for _, r := range raw {
		ctr := Container{
			ID:      r.ID,
			Image:   r.Image,
			ImageID: r.ImageID,
			State:   r.State,
			Labels:  r.Labels,
		}
		if len(r.Names) > 0 {
			ctr.Name = strings.TrimPrefix(r.Names[0], "/")
		}
		for _, p := range r.Ports {
			// A mapping with no public port is not published; it is the
			// container's own EXPOSE, which reaches nothing from the host.
			if p.PublicPort == 0 {
				continue
			}
			ctr.Ports = append(ctr.Ports, PortMapping{
				HostIP:        p.IP,
				HostPort:      p.PublicPort,
				ContainerPort: p.PrivatePort,
				Protocol:      strings.ToLower(p.Type),
			})
		}
		out = append(out, ctr)
	}
	return out, nil
}

// Inspect fills in the details the list endpoint omits: the manifest digest,
// and what the container was told to run.
func (c *Client) Inspect(ctx context.Context, id string) (Container, error) {
	var raw struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Image  string `json:"Image"`
		Config struct {
			Image      string            `json:"Image"`
			Entrypoint []string          `json:"Entrypoint"`
			Cmd        []string          `json:"Cmd"`
			Labels     map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := c.get(ctx, "/containers/"+id+"/json", &raw); err != nil {
		return Container{}, err
	}
	out := Container{
		ID:         raw.ID,
		Name:       strings.TrimPrefix(raw.Name, "/"),
		Image:      raw.Config.Image,
		ImageID:    raw.Image,
		Entrypoint: raw.Config.Entrypoint,
		Command:    raw.Config.Cmd,
		Labels:     raw.Config.Labels,
	}
	out.Digest = c.imageDigest(ctx, raw.Image)
	return out, nil
}

// imageDigest resolves an image's repo digest -- the "repo@sha256:..." form,
// which is what an image scanner elsewhere will have seen.
//
// RepoDigests rather than Id, because Id is the local image identifier and an
// image built here and never pushed has no repo digest at all; reporting the
// local one in its place would be a value matching nobody else's record of the
// same image.
//
// The two are not always different, and this was checked rather than assumed:
// on a Docker 29 daemon using the containerd image store, RepoDigests reported
// exactly the same sha256 as Id for a pulled image. So callers must not treat
// a repo digest differing from the id as a precondition, and swinv reports
// both rather than deciding which one the reader wanted.
func (c *Client) imageDigest(ctx context.Context, imageID string) string {
	if imageID == "" {
		return ""
	}
	var raw struct {
		RepoDigests []string `json:"RepoDigests"`
	}
	if err := c.get(ctx, "/images/"+imageID+"/json", &raw); err != nil {
		return ""
	}
	for _, d := range raw.RepoDigests {
		if _, digest, ok := strings.Cut(d, "@"); ok {
			return digest
		}
	}
	return ""
}

// get performs a GET against the daemon and decodes the response, if out is
// non-nil.
func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+"/"+apiVersion+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("docker %s: %s", path, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

// dialFunc is the shape http.Transport wants.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)
