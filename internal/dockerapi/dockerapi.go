// Package dockerapi reads container state from a local Docker Engine.
//
// This is the one place swinv talks to a daemon, and it is here because on
// Windows there is no alternative. Docker Desktop runs Linux containers inside
// a WSL2 virtual machine: their processes are not Windows processes, they have
// no entry in the Windows process table, and their listening sockets live in
// network namespaces inside that VM. No Windows API reaches them. What Windows
// *can* see is Docker's proxy holding the published port - which is exactly
// the "docker-ce owns port 3000" non-answer the Linux collector exists to
// avoid, and on Windows it cannot be followed any other way.
//
// It remains true that swinv performs no network activity: this is a local
// named pipe (Windows) or Unix socket (Linux), kernel IPC with no address and
// no route. Nothing here reaches a registry or any other host.
//
// Everything is best-effort. A machine with no Docker, a daemon that is not
// running, or a user outside the docker group produces no containers and no
// error - the inventory is not worth failing over a section that could not be
// collected, and the caller records a blind spot instead.
package dockerapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
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
	// State is the runtime's own word: "running", "exited", "created".
	// A stopped container serves nothing, and its declared ports are a
	// statement of intent rather than an observation.
	State string

	// Ports are the published mappings, straight from the daemon. This is the
	// whole reason to ask: it says which host port reaches which container
	// port, exactly, with no argv to parse and no address to guess.
	Ports []PortMapping

	// Entrypoint and Command are what the container was told to run, which is
	// the only description of the workload available without entering it.
	Entrypoint []string
	Command    []string

	// Exposed are the ports the image declares with EXPOSE, whether or not
	// anything is listening on them. For a stopped container this is the only
	// network fact available, and it is a declaration rather than an
	// observation -- which is why it is kept apart from Ports, and why a
	// consumer must not read it as an open port.
	Exposed []PortMapping

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

// Containers lists containers. all includes those that are not running.
//
// A stopped container serves nothing, so it contributes no exposure. It is
// still software present on the machine, which is a different claim and the
// caller's to make.
func (c *Client) Containers(ctx context.Context, all bool) ([]Container, error) {
	path := "/containers/json"
	if all {
		path += "?all=1"
	}
	return c.containers(ctx, path)
}

func (c *Client) containers(ctx context.Context, path string) ([]Container, error) {
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
	if err := c.get(ctx, path, &raw); err != nil {
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
		ID    string `json:"Id"`
		Name  string `json:"Name"`
		Image string `json:"Image"`
		State struct {
			Status string `json:"Status"`
		} `json:"State"`
		Config struct {
			Image        string              `json:"Image"`
			Entrypoint   []string            `json:"Entrypoint"`
			Cmd          []string            `json:"Cmd"`
			Labels       map[string]string   `json:"Labels"`
			ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		} `json:"Config"`
		HostConfig struct {
			PortBindings map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"PortBindings"`
		} `json:"HostConfig"`
	}
	if err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &raw); err != nil {
		return Container{}, err
	}
	out := Container{
		ID:         raw.ID,
		Name:       strings.TrimPrefix(raw.Name, "/"),
		Image:      raw.Config.Image,
		ImageID:    raw.Image,
		State:      raw.State.Status,
		Entrypoint: raw.Config.Entrypoint,
		Command:    raw.Config.Cmd,
		Labels:     raw.Config.Labels,
		Exposed:    exposedPorts(raw.Config.ExposedPorts, raw.HostConfig.PortBindings),
	}
	out.Digest = c.imageDigest(ctx, raw.Image)
	return out, nil
}

// exposedPorts merges what the image declares with what the run configured.
//
// Both are statements of intent: EXPOSE says the image expects to serve there,
// and PortBindings says the run asked for it to be published. Neither is an
// observation, and for a stopped container neither can be one.
func exposedPorts(exposed map[string]struct{}, bindings map[string][]struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}) []PortMapping {
	var out []PortMapping
	seen := map[string]bool{}

	add := func(spec, hostIP string, hostPort uint16) {
		if seen[spec+hostIP+strconv.Itoa(int(hostPort))] {
			return
		}
		seen[spec+hostIP+strconv.Itoa(int(hostPort))] = true
		port, proto := splitPortSpec(spec)
		if port == 0 {
			return
		}
		out = append(out, PortMapping{
			HostIP: hostIP, HostPort: hostPort,
			ContainerPort: port, Protocol: proto,
		})
	}

	for spec, list := range bindings {
		for _, b := range list {
			p, _ := strconv.ParseUint(b.HostPort, 10, 16)
			add(spec, b.HostIP, uint16(p))
		}
	}
	for spec := range exposed {
		add(spec, "", 0)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ContainerPort != out[j].ContainerPort {
			return out[i].ContainerPort < out[j].ContainerPort
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}

// splitPortSpec reads Docker's "8080/tcp" port key.
func splitPortSpec(spec string) (uint16, string) {
	portText, proto, ok := strings.Cut(spec, "/")
	if !ok {
		proto = "tcp"
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return 0, ""
	}
	return uint16(port), strings.ToLower(proto)
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

// getRaw performs a GET and returns the body, for endpoints that are not JSON.
func (c *Client) getRaw(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/"+apiVersion+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("docker %s: %s", path, strings.TrimSpace(string(body)))
	}
	return body, nil
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
