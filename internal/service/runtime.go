package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/chaugan/swinv/internal/ctrpkg"
	"github.com/chaugan/swinv/internal/dockerapi"
	"github.com/chaugan/swinv/internal/model"
)

// runtimeTimeout bounds the whole conversation with a container runtime.
const runtimeTimeout = 60 * time.Second

// RuntimeStatus records what happened when swinv asked a container runtime
// about itself.
//
// It exists because "no containers" has two causes that produce identical
// output: a runtime that answered and had nothing running, and a runtime that
// was never reached. A real Windows run reported zero containers on a machine
// with eight of them, all stopped, and nothing in the report distinguished
// that from a broken pipe.
type RuntimeStatus struct {
	// Reached is true when a runtime answered at all.
	Reached  bool
	Endpoint string

	// Found is how many containers it reported, in any state.
	Found int

	// Err is why it could not be reached, when it could not.
	Err error
}

// Warning renders the status as a line for the report, or "" when there is
// nothing worth saying.
func (s RuntimeStatus) Warning() string {
	switch {
	case s.Reached && s.Found == 0:
		return "a container runtime answered at " + s.Endpoint + " and reported no containers"
	case !s.Reached:
		// Not an error: most machines run no containers, and saying so on
		// every one of them would be noise.
		return ""
	}
	return ""
}

// RuntimeContainers asks the local container runtime what it is running and
// what it has stopped, and reads the software inside each.
//
// Covering stopped containers is deliberate. The question is what software on
// this machine has a network endpoint, and a stopped container that declares
// one is software that will serve on it the moment it is started -- its
// packages carry the same advisories either way. What it does *not* get is an
// exposure row, because nothing is listening.
//
// Containers with no network endpoint at all, declared or observed, are left
// out. That is what keeps the cost proportional to the question: a build
// container with no ports is not part of this machine's attack surface.
func RuntimeContainers(ctx context.Context, existing []model.Container, noCommand bool) ([]model.Container, []model.Component, RuntimeStatus) {
	ctx, cancel := context.WithTimeout(ctx, runtimeTimeout)
	defer cancel()

	client, err := dockerapi.Dial(ctx, runtimeTimeout)
	if err != nil {
		return existing, nil, RuntimeStatus{Err: err}
	}
	status := RuntimeStatus{Reached: true, Endpoint: client.Endpoint()}

	listed, err := client.Containers(ctx, true)
	if err != nil {
		status.Err = err
		return existing, nil, status
	}
	status.Found = len(listed)

	// Whatever the /proc route already resolved stays: it names the package
	// behind a specific listening executable, which is a stronger statement
	// than the whole package list of the filesystem that executable sits in.
	byID := make(map[string]int, len(existing))
	out := append([]model.Container(nil), existing...)
	for i := range out {
		byID[out[i].ID] = i
	}

	var components []model.Component
	for _, c := range listed {
		full, err := client.Inspect(ctx, c.ID)
		if err == nil {
			full.Ports = c.Ports
			if full.Name == "" {
				full.Name = c.Name
			}
			c = full
		}

		declared := declaredEndpoints(c)
		if i, known := byID[c.ID]; known {
			// Already described from /proc. Fill in what the runtime knows and
			// /proc does not.
			out[i].State = c.State
			out[i].DeclaredEndpoints = declared
			if out[i].Name == "" {
				out[i].Name = c.Name
			}
			if out[i].Image == nil {
				out[i].Image = imageOf(c)
			}
			if named(out[i]) {
				continue
			}
			// The targeted probe found the listening executable and no package
			// owning it -- an application unpacked into the image, which is
			// most of them. That says nothing about the rest of the container,
			// and without this a *running* container came out with no software
			// at all while a stopped one got its whole package list. Six of
			// seventeen on the development host.
			components = append(components,
				packageComponents(out[i], readPackages(ctx, client, c.ID))...)
			continue
		}

		if len(declared) == 0 && len(c.Ports) == 0 {
			// No network endpoint, declared or observed. Not part of this
			// machine's attack surface, and not worth a filesystem read.
			continue
		}

		entry, comps := describeFromRuntime(ctx, client, c, declared, noCommand)
		out = append(out, entry)
		components = append(components, comps...)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, components, status
}

// describeFromRuntime builds a container entry from the runtime alone, which
// is the only route for a stopped container and for any container on Windows.
func describeFromRuntime(ctx context.Context, client *dockerapi.Client, c dockerapi.Container,
	declared []string, noCommand bool) (model.Container, []model.Component) {

	out := model.Container{
		ID:                c.ID,
		Name:              c.Name,
		Runtime:           "docker",
		State:             c.State,
		Image:             imageOf(c),
		DeclaredEndpoints: declared,
	}
	if name, namespace, ok := c.PodName(); ok {
		out.Pod = &model.Pod{
			Name: name, Namespace: namespace,
			UID:       c.Labels["io.kubernetes.pod.uid"],
			Container: c.Labels["io.kubernetes.container.name"],
		}
	}

	src := client.Source(ctx, c.ID)
	release := ctrpkg.ReadReleaseFrom(src)
	out.OSID, out.OSVersionID = release.ID, release.VersionID

	// Everything the container's own database records. The targeted probe
	// cannot be asked here: there is no listening process to look up, either
	// because the container is stopped or because its processes are not
	// visible from this platform.
	packages := ctrpkg.All(src, release)

	svc := model.Service{
		Endpoints:  declared,
		Confidence: model.ConfidenceMedium,
	}
	if !noCommand {
		svc.Command = strings.TrimSpace(strings.Join(append(append([]string{}, c.Entrypoint...), c.Command...), " "))
	}
	svc.Evidence = []string{
		fmt.Sprintf("reported by the container runtime, state %s", stateOr(c.State)),
		"these endpoints are declared by the image or the run configuration, not observed",
	}
	if len(packages) > 0 {
		svc.Evidence = append(svc.Evidence, fmt.Sprintf(
			"%d package(s) read from the container's own database", len(packages)))
	} else {
		svc.Evidence = append(svc.Evidence,
			"no package database was found inside the container, so its software could not be named")
	}
	for _, p := range c.Ports {
		svc.PublishedAs = append(svc.PublishedAs,
			fmt.Sprintf("%s:%d/%s", hostAddressOr(p.HostIP), p.HostPort, p.Protocol))
	}
	svc.PublishedAs = model.SortedSet(svc.PublishedAs)
	out.Services = []model.Service{svc}

	return out, packageComponents(out, packages)
}

// packageComponents lifts a container's packages into the inventory.
func packageComponents(c model.Container, packages []ctrpkg.Owner) []model.Component {
	out := make([]model.Component, 0, len(packages))
	for _, p := range packages {
		if p.PURL == "" {
			continue
		}
		attributes := map[string]string{
			"scan_scope":   "container-package-database",
			"container_id": c.ID,
		}
		if c.Name != "" {
			attributes["container_name"] = c.Name
		}
		if c.State != "" {
			attributes["container_state"] = c.State
		}
		if c.Image != nil {
			if c.Image.Ref != "" {
				attributes["container_image"] = c.Image.Ref
			}
			if c.Image.ManifestDigest != "" {
				attributes["container_image_digest"] = c.Image.ManifestDigest
			}
		}
		out = append(out, model.Component{
			Name: p.Name, Version: p.Version, Type: p.Type, PURL: p.PURL,
			Root:       "container:" + shortID(c.ID),
			FoundBy:    "container-runtime-probe",
			Attributes: attributes,
		})
	}
	return out
}

// named reports whether anything in a container was tied to software.
func named(c model.Container) bool {
	for _, s := range c.Services {
		if len(s.Components) > 0 {
			return true
		}
	}
	return false
}

// readPackages lists a container's own package database through the runtime.
func readPackages(ctx context.Context, client *dockerapi.Client, id string) []ctrpkg.Owner {
	src := client.Source(ctx, id)
	return ctrpkg.All(src, ctrpkg.ReadReleaseFrom(src))
}

// declaredEndpoints renders the ports a container says it serves on.
func declaredEndpoints(c dockerapi.Container) []string {
	var out []string
	for _, p := range c.Exposed {
		out = append(out, fmt.Sprintf("%d/%s", p.ContainerPort, p.Protocol))
	}
	for _, p := range c.Ports {
		out = append(out, fmt.Sprintf("%d/%s", p.ContainerPort, p.Protocol))
	}
	return model.SortedSet(out)
}

func imageOf(c dockerapi.Container) *model.Image {
	if c.Image == "" && c.Digest == "" {
		return nil
	}
	return &model.Image{
		Ref:            c.Image,
		ManifestDigest: c.Digest,
		ID:             c.ImageID,
		PURL:           imagePURL(c.Image, c.Digest),
	}
}

func stateOr(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func hostAddressOr(ip string) string {
	if ip == "" {
		return "0.0.0.0"
	}
	return ip
}
