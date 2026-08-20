package output

import (
	"fmt"
	"io"
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
	for _, c := range r.Components {
		components = append(components, cdxComponent(c, refs))
	}

	bom := cyclonedx.NewBOM()
	bom.Metadata = &cyclonedx.Metadata{
		Timestamp:  formatScannedAt(r.Scan.StartedAt),
		Tools:      cdxTools(r.Tool),
		Component:  cdxHostComponent(r.Host),
		Properties: cdxScanProperties(r),
	}
	bom.Components = &components

	enc := cyclonedx.NewBOMEncoder(w, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	enc.SetEscapeHTML(false)
	if err := enc.EncodeVersion(bom, cyclonedx.SpecVersion1_6); err != nil {
		return fmt.Errorf("output: encoding cyclonedx: %w", err)
	}
	return nil
}

// cdxComponent maps one inventory component. refs accumulates the bom-refs
// already handed out so that two components that share a PURL — legitimate
// when they differ only by type — still get distinct references.
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
// was complete — a consumer must be able to tell a thin inventory from a
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

// appendProp appends a property, skipping empty values so that absent facts
// are absent from the document rather than present and blank.
func appendProp(props []cyclonedx.Property, name, value string) []cyclonedx.Property {
	if value == "" {
		return props
	}
	return append(props, cyclonedx.Property{Name: name, Value: value})
}
