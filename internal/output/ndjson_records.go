package output

import (
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// NDJSON record types. A consumer that understands only component records can
// skip anything carrying one of these, which is why they exist at all.
const (
	recordHeartbeat = "heartbeat"
	recordExposure  = "exposure"
	recordContainer = "container"
)

// exposureLine is one (port, component) pair.
//
// Denormalised deliberately: a port served by three packages becomes three
// records, so a vulnerability finding can be joined on the package alone
// without the consumer unpacking an array. A port with nothing attributed
// still gets a record, with no purl -- a port answering with no package behind
// it is a gap in what can be seen, not a port that is safe, and dropping it
// here would hide it completely.
//
// Every optional field is omitempty. A JSON null is indexed by Splunk as the
// four-character string "null", so a null unit gives every listener on the
// host a systemd unit named "null" and coalesce() cannot tell the difference.
// Omitting the key says the same thing without the trap.
type exposureLine struct {
	RecordType string `json:"record_type"`
	Hostname   string `json:"hostname"`
	ScannedAt  string `json:"scanned_at"`

	Address   string `json:"address"`
	Port      uint16 `json:"port"`
	Protocol  string `json:"protocol"`
	Family    string `json:"family,omitempty"`
	BindScope string `json:"bind_scope"`

	// PURL of the software behind this port. Absent when nothing could be
	// attributed, which the consumer reports as "ports with no package".
	PURL string `json:"purl,omitempty"`

	Executable string `json:"executable,omitempty"`
	Unit       string `json:"unit,omitempty"`
	User       string `json:"user,omitempty"`
	Processes  int    `json:"processes,omitempty"`
	Confidence string `json:"confidence,omitempty"`

	// OSComponent marks a listener that is part of the operating system, which
	// on Windows is most of them. Without it a consumer ranking unattributed
	// ports sees several dozen svchost entries per host.
	OSComponent bool `json:"os_component,omitempty"`

	ContainerID   string `json:"container_id,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
}

// containerLine is one container, running or stopped.
//
// Stopped ones are included on purpose: a stopped container is one `docker
// start` from a running one, so its vulnerabilities are latent rather than
// absent. A consumer can rank them last; it cannot invent them.
type containerLine struct {
	RecordType string `json:"record_type"`
	Hostname   string `json:"hostname"`
	ScannedAt  string `json:"scanned_at"`

	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name,omitempty"`
	Runtime       string `json:"runtime,omitempty"`
	State         string `json:"state,omitempty"`

	ImageRef    string `json:"image_ref,omitempty"`
	ImageDigest string `json:"image_digest,omitempty"`
	ImagePURL   string `json:"image_purl,omitempty"`

	OSID        string `json:"os_id,omitempty"`
	OSVersionID string `json:"os_version_id,omitempty"`

	PodName      string `json:"pod_name,omitempty"`
	PodNamespace string `json:"pod_namespace,omitempty"`

	// Both the array and a flattened form of it. Splunk's JSON extraction
	// renames an array field with a "{}" suffix, so a search asking for
	// "endpoints" silently gets nothing -- which reported a whole fleet as
	// publishing no ports. The text and count fields cost a few bytes and
	// remove the sharp edge.
	DeclaredEndpoints     []string `json:"declared_endpoints,omitempty"`
	DeclaredEndpointsText string   `json:"declared_endpoints_text,omitempty"`
	NDeclaredEndpoints    int      `json:"n_declared_endpoints"`

	Endpoints     []string `json:"endpoints,omitempty"`
	EndpointsText string   `json:"endpoints_text,omitempty"`
	NEndpoints    int      `json:"n_endpoints"`
}

// exposureLines flattens the exposure array into one record per attributed
// package, or one record with no package where nothing was attributed.
func exposureLines(r *model.Report, scannedAt string) []exposureLine {
	names := containerNames(r.Containers)

	var out []exposureLine
	for _, e := range r.Exposure {
		base := exposureLine{
			RecordType:  recordExposure,
			Hostname:    r.Host.Hostname,
			ScannedAt:   scannedAt,
			Address:     e.Address,
			Port:        e.Port,
			Protocol:    e.Protocol,
			Family:      e.Family,
			BindScope:   string(e.BindScope),
			Executable:  e.Executable,
			Unit:        e.Unit,
			User:        e.User,
			Processes:   e.Processes,
			Confidence:  string(e.Confidence),
			OSComponent: e.OSComponent,
			ContainerID: e.Container,
		}
		// A published port names the container behind it, not the forwarder.
		if e.Backend != nil && e.Backend.Container != "" {
			base.ContainerID = e.Backend.Container
			base.Executable = e.Backend.Executable
		}
		base.ContainerName = names[base.ContainerID]

		if len(e.Components) == 0 {
			out = append(out, base)
			continue
		}
		for _, purl := range e.Components {
			row := base
			row.PURL = purl
			out = append(out, row)
		}
	}
	return out
}

// containerLines renders one record per container.
func containerLines(r *model.Report, scannedAt string) []containerLine {
	out := make([]containerLine, 0, len(r.Containers))
	for _, c := range r.Containers {
		line := containerLine{
			RecordType:        recordContainer,
			Hostname:          r.Host.Hostname,
			ScannedAt:         scannedAt,
			ContainerID:       c.ID,
			ContainerName:     c.Name,
			Runtime:           c.Runtime,
			State:             c.State,
			OSID:              c.OSID,
			OSVersionID:       c.OSVersionID,
			DeclaredEndpoints: c.DeclaredEndpoints,
		}
		if c.Image != nil {
			line.ImageRef = c.Image.Ref
			line.ImageDigest = c.Image.ManifestDigest
			line.ImagePURL = c.Image.PURL
		}
		if c.Pod != nil {
			line.PodName = c.Pod.Name
			line.PodNamespace = c.Pod.Namespace
		}

		var endpoints []string
		for _, s := range c.Services {
			endpoints = append(endpoints, s.Endpoints...)
		}
		line.Endpoints = model.SortedSet(endpoints)

		line.DeclaredEndpointsText = strings.Join(line.DeclaredEndpoints, multiValueSep)
		line.NDeclaredEndpoints = len(line.DeclaredEndpoints)
		line.EndpointsText = strings.Join(line.Endpoints, multiValueSep)
		line.NEndpoints = len(line.Endpoints)

		out = append(out, line)
	}
	return out
}

// containerNames maps container ids to their human names, so an exposure
// record can carry both without the consumer joining.
func containerNames(containers []model.Container) map[string]string {
	out := make(map[string]string, len(containers))
	for _, c := range containers {
		if c.Name != "" {
			out[c.ID] = c.Name
		}
	}
	return out
}
