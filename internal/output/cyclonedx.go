package output

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/chaugan/swinv/internal/model"
)

// Property namespaces. CycloneDX asks that custom property names be
// namespaced by the tool that produced them, so every property swinv adds is
// prefixed with "swinv:".
const (
	propHostPrefix      = "swinv:host:"
	propScanPrefix      = "swinv:scan:"
	propComponentPrefix = "swinv:component:"
	propServicePrefix   = "swinv:service:"
)

// hostBOMRef is the bom-ref of the metadata component describing the scanned
// machine. It is a fixed string rather than a generated identifier so that two
// runs produce byte-identical documents.
const hostBOMRef = "swinv:host"

// WriteCycloneDX writes the report as a CycloneDX 1.6 JSON document.
//
// The mapping is: each model.Component becomes a CycloneDX component of type
// "library" carrying its name, version, PURL, first CPE, and licences, with
// locations recorded as evidence occurrences and the remaining swinv-specific
// fields as namespaced properties. The scanned machine becomes the metadata
// component, with its host facts as properties, and swinv (plus the Syft
// version it was built against) is recorded in metadata.tools.
//
// The document is deterministic: the only timestamp is ScanMeta.StartedAt, no
// serial number is generated, and bom-refs are derived from component identity
// rather than randomly. This is a deliberate departure from the CycloneDX
// convention of a per-document UUID serial number, and it is what lets two
// consecutive inventories be diffed.
//
// It does not import Syft: the document is built from model types directly.
// It does not close w.
func WriteCycloneDX(w io.Writer, r *model.Report) error {
	if r == nil {
		return ErrNilReport
	}

	components := make([]cyclonedx.Component, 0, len(r.Components))
	refs := make(map[string]int, len(r.Components))
	// byIdentity maps the string a service names its software by onto the
	// bom-ref that software actually got, so the dependency graph below points
	// at real components rather than at plausible-looking strings.
	byIdentity := make(map[string]string, len(r.Components))
	for _, c := range r.Components {
		cdx := cdxComponent(c, refs)
		components = append(components, cdx)
		if id := model.Identify(c); id != "" {
			if _, seen := byIdentity[id]; !seen {
				byIdentity[id] = cdx.BOMRef
			}
		}
	}

	// The distribution, as a component of type "operating-system".
	//
	// Not decoration, and not a duplicate of the host metadata: Syft's
	// CycloneDX decoder -- which is what Grype uses to read
	// `grype sbom:report.cdx.json`, a recipe this project documents -- takes
	// the Linux release *only* from a components[] entry of this type. Ours
	// described the machine as metadata.component of type "device", which that
	// decoder does not look at, so every deb and rpm arrived with no distro.
	// Without a distro Grype cannot use the distribution matchers and falls
	// back to CPE matching against NVD, comparing a backported version against
	// upstream's numbering -- the same failure that produced 442 false
	// findings on one host and that Component.OwnedBy exists to prevent, this
	// time caused by the output format rather than the catalog.
	if os := cdxOSComponent(r.Host); os != nil {
		components = append(components, *os)
	}

	bom := cyclonedx.NewBOM()
	bom.Metadata = &cyclonedx.Metadata{
		Timestamp:  formatScannedAt(r.Scan.StartedAt),
		Tools:      cdxTools(r.Tool),
		Component:  cdxHostComponent(r.Host),
		Properties: cdxScanProperties(r),
	}
	bom.Components = &components

	if services, deps := cdxServices(allServices(r), byIdentity); len(services) > 0 {
		bom.Services = &services
		if len(deps) > 0 {
			bom.Dependencies = &deps
		}
	}

	enc := cyclonedx.NewBOMEncoder(w, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	enc.SetEscapeHTML(false)
	if err := enc.EncodeVersion(bom, cyclonedx.SpecVersion1_6); err != nil {
		return fmt.Errorf("output: encoding cyclonedx: %w", err)
	}
	return nil
}

// cdxComponent maps one inventory component. refs accumulates the bom-refs
// already handed out so that two components that share a PURL - legitimate
// when they differ only by type - still get distinct references.
func cdxComponent(c model.Component, refs map[string]int) cyclonedx.Component {
	out := cyclonedx.Component{
		BOMRef:     uniqueRef(componentRef(c), refs),
		Type:       cyclonedx.ComponentTypeLibrary,
		Name:       c.Name,
		Version:    c.Version,
		PackageURL: c.PURL,
		Licenses:   cdxLicenses(c.Licenses),
		// CycloneDX "publisher" is a free-text organisation name, which is
		// exactly the shape of what the ecosystems record. "supplier" is the
		// structured alternative and would require inventing contact details
		// that no cataloger provides.
		Publisher: c.Vendor,
	}

	// CycloneDX carries a single CPE per component; keep the first (the input
	// is sorted, so "first" is stable) and preserve the rest as properties.
	if len(c.CPEs) > 0 {
		out.CPE = c.CPEs[0]
	}

	// SHA-256 has a first-class home in CycloneDX, so use it rather than
	// smuggling the digest through a custom property.
	if c.SHA256 != "" {
		out.Hashes = &[]cyclonedx.Hash{{
			Algorithm: cyclonedx.HashAlgoSHA256,
			Value:     c.SHA256,
		}}
	}

	var props []cyclonedx.Property
	props = appendProp(props, propComponentPrefix+"type", c.Type)
	props = appendProp(props, propComponentPrefix+"change", c.Change)
	props = appendProp(props, propComponentPrefix+"language", c.Language)
	props = appendProp(props, propComponentPrefix+"found_by", c.FoundBy)
	props = appendProp(props, propComponentPrefix+"source", c.Source)

	// Ecosystem-specific identity has no home in the CycloneDX component
	// schema, so it goes to properties under the same prefix as everything
	// else swinv adds. Sorted, because map iteration is not.
	if len(c.Attributes) > 0 {
		keys := make([]string, 0, len(c.Attributes))
		for k := range c.Attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			props = appendProp(props, propComponentPrefix+k, c.Attributes[k])
		}
	}
	if len(c.CPEs) > 1 {
		for _, extra := range c.CPEs[1:] {
			props = appendProp(props, propComponentPrefix+"cpe", extra)
		}
	}
	if len(props) > 0 {
		out.Properties = &props
	}

	if occ := cdxOccurrences(c.Locations); occ != nil {
		out.Evidence = &cyclonedx.Evidence{Occurrences: occ}
	}
	return out
}

// componentRef derives a stable, human-legible bom-ref. The PURL is the
// canonical identifier when Syft supplied one; otherwise the dedup tuple is
// spelled out.
func componentRef(c model.Component) string {
	if c.PURL != "" {
		return c.PURL
	}
	typ := c.Type
	if typ == "" {
		typ = "unknown"
	}
	return typ + ":" + c.Name + "@" + c.Version
}

// uniqueRef returns base, suffixed with an occurrence counter if base has
// already been used. bom-refs must be unique within a document.
func uniqueRef(base string, refs map[string]int) string {
	n := refs[base]
	refs[base] = n + 1
	if n == 0 {
		return base
	}
	return base + "#" + strconv.Itoa(n+1)
}

// cdxOccurrences records each on-disk location as evidence of where the
// component was found. It returns nil when there are no usable locations so
// the evidence object is omitted entirely.
func cdxOccurrences(locations []string) *[]cyclonedx.EvidenceOccurrence {
	out := make([]cyclonedx.EvidenceOccurrence, 0, len(locations))
	for _, l := range locations {
		if l == "" {
			continue
		}
		out = append(out, cyclonedx.EvidenceOccurrence{Location: l})
	}
	if len(out) == 0 {
		return nil
	}
	return &out
}

// cdxLicenses maps swinv's licence strings onto the CycloneDX licence choice.
//
// A lone SPDX expression (one containing an AND/OR/WITH operator or a
// parenthesis) is emitted as an "expression", which the schema only permits
// when it is the sole entry. Everything else becomes a licence object: a
// single token is assumed to be an SPDX identifier and goes in "id", while
// anything containing whitespace is free text and goes in "name". swinv does
// not embed the SPDX licence list, so this is a heuristic rather than
// validation.
func cdxLicenses(in []string) *cyclonedx.Licenses {
	values := make([]string, 0, len(in))
	for _, l := range in {
		if l = strings.TrimSpace(l); l != "" {
			values = append(values, l)
		}
	}
	if len(values) == 0 {
		return nil
	}

	if len(values) == 1 && isLicenseExpression(values[0]) {
		licenses := cyclonedx.Licenses{{Expression: values[0]}}
		return &licenses
	}

	licenses := make(cyclonedx.Licenses, 0, len(values))
	for _, v := range values {
		if strings.ContainsAny(v, " \t") {
			licenses = append(licenses, cyclonedx.LicenseChoice{License: &cyclonedx.License{Name: v}})
			continue
		}
		licenses = append(licenses, cyclonedx.LicenseChoice{License: &cyclonedx.License{ID: v}})
	}
	return &licenses
}

// isLicenseExpression reports whether s looks like a compound SPDX expression
// rather than a bare identifier. SPDX operators are uppercase by definition.
func isLicenseExpression(s string) bool {
	if strings.ContainsAny(s, "()") {
		return true
	}
	for _, op := range []string{" AND ", " OR ", " WITH "} {
		if strings.Contains(s, op) {
			return true
		}
	}
	return false
}

// cdxTools records the producers of the document: swinv itself, and the Syft
// version it was built against, which is what actually did the cataloging.
func cdxTools(t model.Tool) *cyclonedx.ToolsChoice {
	name := t.Name
	if name == "" {
		name = "swinv"
	}

	swinv := cyclonedx.Component{
		BOMRef:  "swinv:tool:" + name,
		Type:    cyclonedx.ComponentTypeApplication,
		Name:    name,
		Version: t.Version,
	}
	if t.Commit != "" {
		props := []cyclonedx.Property{{Name: "swinv:tool:commit", Value: t.Commit}}
		swinv.Properties = &props
	}

	tools := []cyclonedx.Component{swinv}
	if t.SyftVersion != "" {
		tools = append(tools, cyclonedx.Component{
			BOMRef:  "swinv:tool:syft",
			Type:    cyclonedx.ComponentTypeApplication,
			Group:   "anchore",
			Name:    "syft",
			Version: t.SyftVersion,
		})
	}
	return &cyclonedx.ToolsChoice{Components: &tools}
}

// cdxOSComponent renders the distribution the way every other SBOM producer
// does, so that an SBOM consumer finds it where it looks for it.
//
// The property names are Syft's ("syft:distro:id" and friends) rather than
// swinv's own namespace, deliberately: they are what Syft's decoder reads, and
// a namespaced-but-unread property would be correct and useless.
func cdxOSComponent(h model.Host) *cyclonedx.Component {
	if h.OSID == "" {
		return nil
	}
	out := &cyclonedx.Component{
		BOMRef:      "swinv:distro:" + h.OSID + "@" + h.OSVersionID,
		Type:        cyclonedx.ComponentTypeOS,
		Name:        h.OSID,
		Version:     h.OSVersionID,
		Description: h.OSPrettyName,
	}
	var props []cyclonedx.Property
	props = appendProp(props, "syft:distro:id", h.OSID)
	props = appendProp(props, "syft:distro:versionID", h.OSVersionID)
	props = appendProp(props, "syft:distro:prettyName", h.OSPrettyName)
	if len(props) > 0 {
		out.Properties = &props
	}
	return out
}

// cdxHostComponent maps the scanned machine onto the metadata component. Every
// host fact is optional, so each becomes a property only when populated.
func cdxHostComponent(h model.Host) *cyclonedx.Component {
	name := h.Hostname
	if name == "" {
		// CycloneDX requires a component name; an unreadable hostname must not
		// produce an invalid document.
		name = "unknown-host"
	}

	var props []cyclonedx.Property
	props = appendProp(props, propHostPrefix+"hostname", h.Hostname)
	props = appendProp(props, propHostPrefix+"fqdn", h.FQDN)
	props = appendProp(props, propHostPrefix+"machine_id", h.MachineID)
	props = appendProp(props, propHostPrefix+"boot_id", h.BootID)
	props = appendProp(props, propHostPrefix+"os_id", h.OSID)
	props = appendProp(props, propHostPrefix+"os_version_id", h.OSVersionID)
	props = appendProp(props, propHostPrefix+"os_pretty_name", h.OSPrettyName)
	props = appendProp(props, propHostPrefix+"kernel_release", h.KernelRelease)
	props = appendProp(props, propHostPrefix+"architecture", h.Architecture)
	props = appendProp(props, propHostPrefix+"virtualization", h.Virtualization)
	props = appendProp(props, propHostPrefix+"system_vendor", h.SystemVendor)
	props = appendProp(props, propHostPrefix+"product_name", h.ProductName)
	props = appendProp(props, propHostPrefix+"product_serial", h.ProductSerial)
	props = appendProp(props, propHostPrefix+"product_uuid", h.ProductUUID)
	// Duplicate property names are permitted, so multi-valued facts are
	// emitted one property per value rather than joined into one string.
	for _, v := range h.IPv4 {
		props = appendProp(props, propHostPrefix+"ipv4", v)
	}
	for _, v := range h.IPv6 {
		props = appendProp(props, propHostPrefix+"ipv6", v)
	}
	for _, v := range h.MACs {
		props = appendProp(props, propHostPrefix+"mac", v)
	}

	out := &cyclonedx.Component{
		BOMRef:      hostBOMRef,
		Type:        cyclonedx.ComponentTypeDevice,
		Name:        name,
		Description: h.OSPrettyName,
	}
	if len(props) > 0 {
		out.Properties = &props
	}
	return out
}

// cdxScanProperties records how the scan was performed, including whether it
// was complete - a consumer must be able to tell a thin inventory from a
// broken one without reading swinv's own JSON.
func cdxScanProperties(r *model.Report) *[]cyclonedx.Property {
	var props []cyclonedx.Property
	props = appendProp(props, "swinv:schema_version", r.SchemaVersion)
	props = appendProp(props, propScanPrefix+"root", r.Scan.Root)
	props = appendProp(props, propScanPrefix+"started_at", formatScannedAt(r.Scan.StartedAt))
	props = appendProp(props, propScanPrefix+"finished_at", formatScannedAt(r.Scan.FinishedAt))
	props = appendProp(props, propScanPrefix+"duration_ms", strconv.FormatInt(r.Scan.DurationMS, 10))
	props = appendProp(props, propScanPrefix+"ran_as_root", strconv.FormatBool(r.Scan.RanAsRoot))
	props = appendProp(props, propScanPrefix+"incomplete", strconv.FormatBool(r.Scan.Incomplete))
	for _, c := range r.Scan.Catalogers {
		props = appendProp(props, propScanPrefix+"cataloger", c)
	}
	for _, e := range r.Scan.Excluded {
		props = appendProp(props, propScanPrefix+"excluded", e)
	}
	for _, warning := range r.Scan.Warnings {
		props = appendProp(props, propScanPrefix+"warning", warning)
	}
	if len(props) == 0 {
		return nil
	}
	return &props
}

// cdxService pairs a service with the trust zone it listens in.
type cdxService struct {
	service model.Service
	zone    string
	group   string
}

// Trust zones, as CycloneDX's own "trustZone" field.
//
// Deliberately not x-trust-boundary: that is a boolean about whether *using* a
// service crosses a boundary, which other tools read that way, and overloading
// it to mean "bound to a non-loopback address" would produce wrong conclusions
// in software this project does not control. trustZone is a name, which is
// what these are.
const (
	zoneHostNetwork      = "host-network"
	zoneHostLoopback     = "host-loopback"
	zoneContainerNetwork = "container-network"
)

// allServices flattens the host services and every container's services into
// one list, each tagged with the zone it listens in.
//
// The zone is what keeps the two apart in a format that has one services
// array. A container's 0.0.0.0 bind is not reachable at this machine's
// addresses, and a consumer reading this document must not have to infer that
// from a group name.
func allServices(r *model.Report) []cdxService {
	out := make([]cdxService, 0, len(r.Services))
	for _, s := range r.Services {
		out = append(out, cdxService{service: s, zone: hostZone(s)})
	}
	for _, c := range r.Containers {
		group := c.Name
		if group == "" {
			group = shortContainerID(c.ID)
		}
		for _, s := range c.Services {
			out = append(out, cdxService{service: s, zone: zoneContainerNetwork, group: group})
		}
	}
	return out
}

// hostZone reports whether a host service is bound beyond loopback. The
// exposure array carries the per-socket verdict; this is the rollup the
// services array can express.
func hostZone(s model.Service) string {
	for _, e := range s.Endpoints {
		if !strings.HasPrefix(e, "127.") && !strings.HasPrefix(e, "[::1]") {
			return zoneHostNetwork
		}
	}
	return zoneHostLoopback
}

func shortContainerID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// cdxServices maps the report's services onto CycloneDX services, and returns
// the dependency edges linking each one to the components that implement it.
//
// CycloneDX has a first-class service type, and it is the right home for this:
// a consumer that already reads SBOMs gets "what is listening, and which of
// these components is behind it" without learning an swinv-specific shape. The
// endpoints go in the schema's own "endpoints" field; everything swinv knows
// that the schema has no field for -- pid, unit, container, confidence, the
// evidence trail -- becomes a namespaced property.
//
// The aggregate entry for sockets that could not be attributed to a process
// carries no endpoints and no name of its own; it is still emitted, because a
// document that quietly omits "and there were 38 more I could not see" is
// making a stronger claim than the scan supports.
func cdxServices(in []cdxService, byIdentity map[string]string) ([]cyclonedx.Service, []cyclonedx.Dependency) {
	if len(in) == 0 {
		return nil, nil
	}

	services := make([]cyclonedx.Service, 0, len(in))
	deps := make([]cyclonedx.Dependency, 0, len(in))
	refs := make(map[string]int, len(in))

	for _, entry := range in {
		s := entry.service
		ref := uniqueRef(serviceRef(s), refs)
		out := cyclonedx.Service{
			BOMRef:    ref,
			Name:      serviceName(s),
			Group:     entry.group,
			TrustZone: entry.zone,
		}
		if len(s.Endpoints) > 0 {
			endpoints := append([]string(nil), s.Endpoints...)
			out.Endpoints = &endpoints
		}

		var props []cyclonedx.Property
		props = appendProp(props, propServicePrefix+"confidence", string(s.Confidence))
		props = appendProp(props, propServicePrefix+"executable", s.Executable)
		props = appendProp(props, propServicePrefix+"command", s.Command)
		props = appendProp(props, propServicePrefix+"unit", s.Unit)
		props = appendProp(props, propServicePrefix+"container", s.Container)
		props = appendProp(props, propServicePrefix+"user", s.User)
		if s.PID != 0 {
			props = appendProp(props, propServicePrefix+"pid", strconv.Itoa(s.PID))
		}
		if s.SocketActivated {
			props = appendProp(props, propServicePrefix+"socket_activated", "true")
		}
		if s.Processes > 1 {
			props = appendProp(props, propServicePrefix+"processes", strconv.Itoa(s.Processes))
		}
		for _, p := range s.PublishedAs {
			props = appendProp(props, propServicePrefix+"published_as", p)
		}
		// Duplicate property names are permitted, so the evidence trail is one
		// property per line rather than a joined blob.
		for _, e := range s.Evidence {
			props = appendProp(props, propServicePrefix+"evidence", e)
		}
		if len(props) > 0 {
			out.Properties = &props
		}
		services = append(services, out)

		// dependsOn is the edge that makes this worth emitting: it is how a
		// consumer answers "is anything internet-facing running the component
		// this advisory is about".
		var on []string
		for _, id := range s.Components {
			if target, ok := byIdentity[id]; ok {
				on = append(on, target)
			}
		}
		// The shared libraries the service loads are dependencies in exactly
		// CycloneDX's sense, and the packages behind them are already in
		// components[] -- so a consumer walking the graph from a service now
		// reaches libssl without knowing anything swinv-specific.
		for _, l := range s.Links {
			if l.PURL == "" {
				continue
			}
			if target, ok := byIdentity[l.PURL]; ok {
				on = append(on, target)
			}
		}
		on = model.SortedSet(on)
		if len(on) > 0 {
			deps = append(deps, cyclonedx.Dependency{Ref: ref, Dependencies: &on})
		}
	}
	return services, deps
}

// serviceName is what a human scanning the document reads first. The systemd
// unit is the best answer where there is one, since it is the name the
// operator already uses for the thing; the executable's basename is the next
// best.
func serviceName(s model.Service) string {
	switch {
	case s.Unit != "":
		return s.Unit
	case s.Executable != "":
		// Backslashes are replaced explicitly rather than with
		// filepath.ToSlash, which is a no-op off Windows: the writer is not
		// necessarily running on the platform the report describes.
		return path.Base(strings.ReplaceAll(s.Executable, `\`, "/"))
	case len(s.Endpoints) > 0:
		return s.Endpoints[0]
	default:
		return "unattributed-listeners"
	}
}

// serviceRef derives a stable bom-ref. It deliberately does not include the
// pid: a document diffed against yesterday's should not show every service
// replaced because the machine rebooted.
func serviceRef(s model.Service) string {
	return "swinv:service:" + serviceName(s)
}

// appendProp appends a property, skipping empty values so that absent facts
// are absent from the document rather than present and blank.
func appendProp(props []cyclonedx.Property, name, value string) []cyclonedx.Property {
	if value == "" {
		return props
	}
	return append(props, cyclonedx.Property{Name: name, Value: value})
}
