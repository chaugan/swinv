//go:build linux

package service

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/chaugan/swinv/internal/ctrpkg"
	"github.com/chaugan/swinv/internal/model"
)

// EnrichContainers resolves what each container is and what its listening
// software is, by reading the container's own filesystem through
// /proc/<pid>/root.
//
// This is where the requirement "the PURL of the service, even if it is in
// Docker or Kubernetes" is actually met. The container's own package database
// answers it -- pkg:rpm/rhel/bash@4.4.20-6.el8_10 from a RHEL container on an
// Ubuntu host -- and that is a coordinate Grype and Trivy match today. The
// image reference cannot do this job: there is no oci matcher anywhere in the
// chain, so an image PURL alone produces a component that is reported clean
// because nothing ever looked at it.
func EnrichContainers(procRoot string, containers []Container, noCommand bool) []model.Container {
	if len(containers) == 0 {
		return nil
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	out := make([]model.Container, 0, len(containers))
	for _, c := range containers {
		out = append(out, enrichOne(procRoot, c, noCommand))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func enrichOne(procRoot string, c Container, noCommand bool) model.Container {
	out := model.Container{ID: c.ID}

	root := filepath.Join(procRoot, strconv.Itoa(c.RootPID), "root")
	release := ctrpkg.ReadRelease(root)
	out.OSID, out.OSVersionID = release.ID, release.VersionID

	// Runtime metadata is best-effort throughout. It is private, undocumented
	// on-disk state that differs per runtime and moves between versions, so
	// nothing here may be required for a container to be reported -- its
	// absence costs a name and a digest, not the finding.
	meta := readRuntimeMetadata(c.ID)
	out.Name, out.Runtime, out.Image, out.Pod = meta.name, meta.runtime, meta.image, meta.pod

	// The paths worth asking about: the executables that are listening. Same
	// discipline as the host join -- probe a short list rather than invert the
	// package database into an index.
	var exes []string
	seen := map[string]bool{}
	for _, s := range c.Services {
		if s.Process.Exe != "" && !seen[s.Process.Exe] {
			seen[s.Process.Exe] = true
			exes = append(exes, s.Process.Exe)
		}
	}
	owners := ctrpkg.Probe(root, exes, release)

	for _, s := range c.Services {
		out.Services = append(out.Services, containerService(s, owners, release, noCommand))
	}
	out.Services = collapseWorkers(out.Services)
	return out
}

// collapseWorkers folds a prefork server's workers back into one service.
//
// nginx's master and its workers all hold the same inherited listening socket,
// so following socket to process finds nine processes where an operator would
// say there is one nginx. Reporting nine misstates both what is running and
// how much of it, and repeats the same identity nine times in every downstream
// count. They are folded when they agree on both the executable and the exact
// set of endpoints -- two genuinely different daemons from the same binary
// listen on different ports and stay separate.
func collapseWorkers(services []model.Service) []model.Service {
	if len(services) < 2 {
		return services
	}
	type key struct{ exe, endpoints string }

	out := make([]model.Service, 0, len(services))
	at := make(map[key]int, len(services))
	for _, s := range services {
		k := key{s.Executable, strings.Join(s.Endpoints, ",")}
		if i, ok := at[k]; ok && s.Executable != "" {
			out[i].Processes++
			// The lowest pid is the master, and the one worth reporting.
			if s.PID != 0 && (out[i].PID == 0 || s.PID < out[i].PID) {
				out[i].PID = s.PID
			}
			continue
		}
		at[k] = len(out)
		s.Processes = 1
		out = append(out, s)
	}
	for i := range out {
		if out[i].Processes < 2 {
			out[i].Processes = 0 // the ordinary case says nothing
		}
	}
	return out
}

func containerService(s Service, owners map[string]ctrpkg.Owner, release ctrpkg.Release, noCommand bool) model.Service {
	out := model.Service{
		PID:        s.Process.PID,
		Executable: s.Process.Exe,
		Unit:       s.Process.Unit,
		Container:  s.Process.Container,
		User:       s.Process.User,
	}
	if !noCommand {
		out.Command = s.Process.Command
	}
	for _, e := range s.Endpoints {
		out.Endpoints = append(out.Endpoints, e.String())
	}
	out.Evidence = append(out.Evidence, fmt.Sprintf(
		"listening inside the container's own network namespace, which is reachable "+
			"from this host only if something publishes it"))

	if s.Process.Exe == "" {
		out.Confidence = model.ConfidenceLow
		out.Evidence = append(out.Evidence, "the executable could not be read")
		return out
	}
	out.Evidence = append(out.Evidence, "executable "+s.Process.Exe)
	if release.ID != "" {
		out.Evidence = append(out.Evidence, fmt.Sprintf(
			"the container's own os-release says %s %s", release.ID, release.VersionID))
	}

	owner, ok := owners[s.Process.Exe]
	if !ok || owner.PURL == "" {
		out.Confidence = model.ConfidenceMedium
		out.Evidence = append(out.Evidence,
			"no package in the container's own database owns this executable, so it "+
				"was unpacked into the image rather than installed")
		return out
	}
	out.Components = []string{owner.PURL}
	out.Confidence = model.ConfidenceHigh
	out.Evidence = append(out.Evidence,
		"the container's package database records "+owner.PURL+" as owning this file")
	return out
}
