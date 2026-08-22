//go:build linux

package service

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// runtimeMetadata is what a container runtime's own on-disk state says about a
// container.
type runtimeMetadata struct {
	name    string
	runtime string
	image   *model.Image
	pod     *model.Pod
}

// maxMetaBytes caps each metadata file read.
const maxMetaBytes = 8 << 20

// readRuntimeMetadata is entirely best-effort.
//
// Everything it reads is private, undocumented daemon state: Docker's
// config.v2.json has changed shape across versions, is absent when data-root
// is set or under rootless, and does not exist for containerd, CRI-O or
// Podman. So nothing here may be required for a container to be reported. Its
// absence costs a display name and an image digest -- neither of which is an
// identity a vulnerability matcher can use anyway; that comes from the
// container's own package database.
func readRuntimeMetadata(id string) runtimeMetadata {
	if id == "" {
		return runtimeMetadata{}
	}
	if meta, ok := readDockerMetadata(id); ok {
		return meta
	}
	if meta, ok := readOCIBundleMetadata(id); ok {
		return meta
	}
	return runtimeMetadata{}
}

// readDockerMetadata reads the Docker daemon's per-container state.
func readDockerMetadata(id string) (runtimeMetadata, bool) {
	raw, err := readCapped(filepath.Join("/var/lib/docker/containers", id, "config.v2.json"))
	if err != nil {
		return runtimeMetadata{}, false
	}
	var cfg struct {
		Name   string `json:"Name"`
		Image  string `json:"Image"`
		Config struct {
			Image string `json:"Image"`
		} `json:"Config"`
		ImageManifest struct {
			Digest string `json:"digest"`
		} `json:"ImageManifest"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return runtimeMetadata{}, false
	}

	meta := runtimeMetadata{
		name:    strings.TrimPrefix(cfg.Name, "/"),
		runtime: "docker",
	}
	if cfg.Config.Image != "" || cfg.ImageManifest.Digest != "" {
		meta.image = &model.Image{
			Ref: cfg.Config.Image,
			// The *manifest* digest, which is what "repo@sha256:..." means and
			// what an image scanner will have seen. cfg.Image is the local
			// config digest, a different value; conflating the two is the
			// classic bug here, so both are kept and named.
			ManifestDigest: cfg.ImageManifest.Digest,
			ID:             cfg.Image,
		}
		meta.image.PURL = imagePURL(cfg.Config.Image, cfg.ImageManifest.Digest)
	}
	return meta, true
}

// ociBundleRoots are where runc-compatible runtimes keep the bundle config.
// The containerd namespace segment differs by who is driving it: "moby" for
// Docker, "k8s.io" for Kubernetes.
var ociBundleRoots = []string{
	"/run/containerd/io.containerd.runtime.v2.task/k8s.io",
	"/run/containerd/io.containerd.runtime.v2.task/moby",
	"/run/containerd/io.containerd.runtime.v2.task/default",
	"/run/crio",
	"/run/runc",
}

// readOCIBundleMetadata reads the OCI runtime bundle's annotations.
//
// The *path* is a containerd implementation detail that has moved once already
// and differs per runtime, so it is tried and forgiven. The *annotation keys*
// are a de-facto CRI contract set by every CRI implementation, so what is
// found there can be trusted. Nothing is inferred: a pod is reported only when
// its name was read.
func readOCIBundleMetadata(id string) (runtimeMetadata, bool) {
	for _, root := range ociBundleRoots {
		raw, err := readCapped(filepath.Join(root, id, "config.json"))
		if err != nil {
			continue
		}
		var spec struct {
			Annotations map[string]string `json:"annotations"`
		}
		if err := json.Unmarshal(raw, &spec); err != nil {
			continue
		}
		meta := runtimeMetadata{runtime: runtimeOf(root)}
		a := spec.Annotations
		meta.name = a["io.kubernetes.container.name"]
		if ref := a["io.kubernetes.cri.image-name"]; ref != "" {
			meta.image = &model.Image{Ref: ref, PURL: imagePURL(ref, "")}
		}
		if name := a["io.kubernetes.pod.name"]; name != "" {
			meta.pod = &model.Pod{
				Name:      name,
				Namespace: a["io.kubernetes.pod.namespace"],
				UID:       a["io.kubernetes.pod.uid"],
				Container: a["io.kubernetes.container.name"],
			}
		}
		return meta, true
	}
	return runtimeMetadata{}, false
}

func runtimeOf(bundleRoot string) string {
	switch {
	case strings.Contains(bundleRoot, "crio"):
		return "cri-o"
	case strings.HasSuffix(bundleRoot, "moby"):
		return "docker"
	case strings.Contains(bundleRoot, "containerd"):
		return "containerd"
	default:
		return "runc"
	}
}

// readCapped reads a file, refusing anything implausibly large or irregular.
func readCapped(name string) ([]byte, error) {
	f, err := os.Open(name) // #nosec G304 -- fixed runtime state paths, capped below
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}
	return io.ReadAll(io.LimitReader(f, maxMetaBytes))
}
