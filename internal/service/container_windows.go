//go:build windows

package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/chaugan/swinv/internal/dockerapi"
	"github.com/chaugan/swinv/internal/model"
)

// dockerTimeout bounds the whole conversation with the engine. It is a local
// pipe, so it either answers promptly or it is not worth waiting for during an
// inventory scan.
const dockerTimeout = 15 * time.Second

// EnrichContainers describes the containers running on this machine, from the
// engine's own account of them.
//
// On Windows this is the only route. A Docker Desktop container is a Linux
// process inside a WSL2 virtual machine: it has no entry in the Windows
// process table, its listening sockets live in a network namespace inside that
// VM, and no Windows API reaches either. Without asking the engine, a
// published port resolves to Docker's own proxy -- the "docker-ce owns port
// 3000" non-answer this design exists to avoid -- and there is no second way
// to follow it.
//
// What the engine cannot give is what a Linux host reads directly: the
// packages installed inside the container. That needs the container's
// filesystem, which is inside the VM. So container services here name the
// workload and the image and stop there, at medium confidence, and the report
// says why rather than leaving a reader to wonder.
func EnrichContainers(_ string, containers []Container, noCommand bool) []model.Container {
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()

	client, err := dockerapi.Dial(ctx, dockerTimeout)
	if err != nil {
		return nil
	}

	listed, err := client.Containers(ctx)
	if err != nil || len(listed) == 0 {
		return nil
	}

	out := make([]model.Container, 0, len(listed))
	for _, c := range listed {
		// The list endpoint omits the digest and what the container runs.
		if full, err := client.Inspect(ctx, c.ID); err == nil {
			full.Ports = c.Ports
			if full.Name == "" {
				full.Name = c.Name
			}
			c = full
		}
		out = append(out, describeContainer(c, client.Endpoint(), noCommand))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// describeContainer maps one engine record onto the report.
func describeContainer(c dockerapi.Container, endpoint string, noCommand bool) model.Container {
	out := model.Container{
		ID:      c.ID,
		Name:    c.Name,
		Runtime: "docker",
	}
	if c.Image != "" || c.Digest != "" {
		out.Image = &model.Image{
			Ref:            c.Image,
			ManifestDigest: c.Digest,
			ID:             c.ImageID,
			PURL:           imagePURL(c.Image, c.Digest),
		}
	}
	if name, namespace, ok := c.PodName(); ok {
		out.Pod = &model.Pod{
			Name:      name,
			Namespace: namespace,
			UID:       c.Labels["io.kubernetes.pod.uid"],
			Container: c.Labels["io.kubernetes.container.name"],
		}
	}

	svc := model.Service{Confidence: model.ConfidenceMedium}
	if !noCommand {
		svc.Command = strings.TrimSpace(strings.Join(append(append([]string{}, c.Entrypoint...), c.Command...), " "))
	}
	for _, p := range c.Ports {
		svc.Endpoints = append(svc.Endpoints, fmt.Sprintf("0.0.0.0:%d/%s", p.ContainerPort, p.Protocol))
		svc.PublishedAs = append(svc.PublishedAs,
			fmt.Sprintf("%s:%d/%s", hostAddress(p.HostIP), p.HostPort, p.Protocol))
	}
	svc.Endpoints = model.SortedSet(svc.Endpoints)
	svc.PublishedAs = model.SortedSet(svc.PublishedAs)

	svc.Evidence = []string{
		"reported by the Docker engine at " + endpoint,
		"the container's filesystem is inside a virtual machine and is not reachable " +
			"from Windows, so the packages it installs could not be read; run swinv " +
			"inside the container host to identify them",
	}
	if out.Image != nil && out.Image.Ref != "" {
		svc.Evidence = append(svc.Evidence, "image "+out.Image.Ref)
	}
	out.Services = []model.Service{svc}
	return out
}

// hostAddress renders the address a port was published on. Docker records the
// wildcard as an empty string in some versions and "0.0.0.0" in others.
func hostAddress(ip string) string {
	if ip == "" {
		return "0.0.0.0"
	}
	return ip
}

// imagePURL renders the pkg:oci form.
//
// A locator, not an identity: no vulnerability matcher resolves an OCI PURL,
// so it never appears in a Components list. It is here so a consumer can join
// to an image scan performed elsewhere.
func imagePURL(ref, digest string) string {
	if ref == "" {
		return ""
	}
	repo, tag := splitImageRef(ref)
	name := repo
	if i := strings.LastIndex(repo, "/"); i >= 0 {
		name = repo[i+1:]
	}
	if name == "" {
		return ""
	}
	out := "pkg:oci/" + strings.ToLower(name)
	if digest != "" {
		out += "@" + strings.Replace(digest, ":", "%3A", 1)
	}
	var qualifiers []string
	if repo != "" {
		qualifiers = append(qualifiers, "repository_url="+repo)
	}
	if tag != "" {
		qualifiers = append(qualifiers, "tag="+tag)
	}
	if len(qualifiers) > 0 {
		out += "?" + strings.Join(qualifiers, "&")
	}
	return out
}

// splitImageRef separates a reference into repository and tag, leaving a
// registry host with a port intact.
func splitImageRef(ref string) (repo, tag string) {
	repo = ref
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		repo, tag = ref[:i], ref[i+1:]
	}
	if i := strings.Index(repo, "@"); i >= 0 {
		repo = repo[:i]
	}
	return strings.ToLower(repo), tag
}

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
	listed, err := client.Containers(ctx)
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
