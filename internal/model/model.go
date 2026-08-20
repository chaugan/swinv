// Package model defines the output types and schema version for swinv.
//
// This package has no dependencies outside the standard library. Everything
// downstream of internal/scan operates on these types, which is what keeps a
// Syft API break contained to a single package.
package model

import (
	"sort"
	"strings"
	"time"
)

// SchemaVersion is the version of the JSON document shape produced by swinv.
// Bump the minor version for additive changes, the major version for
// breaking ones.
// 1.1 added Component.SHA256 (--hash) and Report.Delta (--since). Both are
// additive and omitted when unused, so a 1.0 consumer still parses a 1.1
// document.
const SchemaVersion = "1.2"

// Report is the top-level document written as JSON.
type Report struct {
	SchemaVersion string      `json:"schema_version"`
	Tool          Tool        `json:"tool"`
	Host          Host        `json:"host"`
	Scan          ScanMeta    `json:"scan"`
	Delta         *Delta      `json:"delta,omitempty"`
	Components    []Component `json:"components"`
}

// Delta is the difference between this scan and an earlier report, produced by
// --since. It is a summary: unless --delta-only was given, Report.Components
// still holds the complete current inventory, so the file remains a
// self-contained inventory rather than only a diff.
type Delta struct {
	// Since is the baseline report the comparison was made against.
	Since string `json:"since"`

	// Only records that Report.Components holds just the changed components
	// rather than the full inventory (--delta-only). It exists so such a
	// report can be refused as a future --since baseline: comparing against a
	// diff would report the entire machine as removed.
	Only bool `json:"delta_only,omitempty"`

	// BaselineAt is the baseline's scan start time.
	BaselineAt time.Time `json:"baseline_at"`

	// BaselineHost is the baseline's hostname, so an accidental comparison
	// against a different machine's report is visible rather than silent.
	BaselineHost string `json:"baseline_host,omitempty"`

	// Added, Removed and Changed are each sorted like Components.
	Added   []Component `json:"added,omitempty"`
	Removed []Component `json:"removed,omitempty"`
	Changed []Change    `json:"changed,omitempty"`
}

// Change is one component whose version moved between two scans.
type Change struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	PURL        string `json:"purl,omitempty"`
}

// ChangeKind labels a component's relationship to the baseline, for the CSV
// "change" column and for --delta-only output.
const (
	ChangeAdded     = "added"
	ChangeRemoved   = "removed"
	ChangeChanged   = "changed"
	ChangeUnchanged = ""
)

// Tool identifies the binary that produced a Report.
type Tool struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Commit      string `json:"commit,omitempty"`
	SyftVersion string `json:"syft_version"`
}

// Host is the identity of the machine that was scanned. Every field is
// optional: an unreadable source yields an empty value rather than an error.
type Host struct {
	Hostname       string   `json:"hostname"`
	FQDN           string   `json:"fqdn,omitempty"`
	MachineID      string   `json:"machine_id,omitempty"`
	BootID         string   `json:"boot_id,omitempty"`
	OSID           string   `json:"os_id,omitempty"`
	OSVersionID    string   `json:"os_version_id,omitempty"`
	OSPrettyName   string   `json:"os_pretty_name,omitempty"`
	KernelRelease  string   `json:"kernel_release,omitempty"`
	Architecture   string   `json:"architecture,omitempty"`
	Virtualization string   `json:"virtualization,omitempty"`
	SystemVendor   string   `json:"system_vendor,omitempty"`
	ProductName    string   `json:"product_name,omitempty"`
	ProductSerial  string   `json:"product_serial,omitempty"`
	ProductUUID    string   `json:"product_uuid,omitempty"`
	IPv4           []string `json:"ipv4,omitempty"`
	IPv6           []string `json:"ipv6,omitempty"`
	MACs           []string `json:"macs,omitempty"`
}

// ScanMeta records how the scan was performed and whether it was complete.
type ScanMeta struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMS int64     `json:"duration_ms"`
	Root       string    `json:"root"`
	Excluded   []string  `json:"excluded,omitempty"`
	Catalogers []string  `json:"catalogers,omitempty"`
	RanAsRoot  bool      `json:"ran_as_root"`
	Incomplete bool      `json:"incomplete"`
	Warnings   []string  `json:"warnings,omitempty"`
}

// Component is one piece of installed software.
type Component struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"`
	Language string `json:"language,omitempty"`

	// Vendor is the organisation behind the component, as its own ecosystem
	// records it: an rpm Vendor, a dpkg or apk Maintainer, or CompanyName from
	// a Windows PE version resource. Those are related but not identical
	// facts, and the raw value is kept rather than normalised — see
	// vendorFromPackage in internal/scan.
	//
	// Frequently empty. Many ecosystems record no such field at all.
	Vendor    string   `json:"vendor,omitempty"`
	PURL      string   `json:"purl,omitempty"`
	CPEs      []string `json:"cpes,omitempty"`
	Licenses  []string `json:"licenses,omitempty"`
	Locations []string `json:"locations,omitempty"`
	FoundBy   string   `json:"found_by,omitempty"`

	// SHA256 is the hex content digest of the component's primary on-disk
	// location. Populated only when --hash is given, because hashing every
	// discovered file is a large amount of extra I/O.
	SHA256 string `json:"sha256,omitempty"`

	// Change labels this component against the --since baseline: one of
	// ChangeAdded, ChangeChanged, ChangeRemoved, or empty for unchanged. It is
	// populated only when --since was given, and is omitted from every format
	// otherwise. ChangeRemoved appears only in --delta-only output, since a
	// removed component is by definition absent from the current inventory.
	Change string `json:"change,omitempty"`
}

// identity is the (name, type) pair used to match a component across two
// scans. Version is deliberately excluded: a version move is what makes a
// component "changed" rather than a removal plus an addition.
type identity struct {
	name string
	typ  string
}

func (c Component) identity() identity {
	return identity{c.Name, c.Type}
}

// ComputeDelta compares the current components against a baseline and reports
// what was added, removed, and version-changed.
//
// Matching is on (Name, Type), then on version within that group. A component
// present in both at a different version is a Change, not a removal plus an
// addition — which is the whole point of running a delta on a daily inventory.
//
// An identity can legitimately hold several versions at once: a Debian host
// normally has two or three linux-image packages installed side by side. Those
// are matched version-by-version first, so an unchanged multi-version identity
// produces no delta at all. Only when exactly one version is left unmatched on
// each side is that pair reported as a Change; anything else is reported as
// explicit additions and removals rather than an invented version move.
//
// Both inputs are assumed to have been through Normalize, so the outputs
// inherit its ordering.
func ComputeDelta(current, baseline []Component) *Delta {
	currentByID := groupByIdentity(current)
	baselineByID := groupByIdentity(baseline)

	d := &Delta{}

	for id, cur := range currentByID {
		base := baselineByID[id]
		addedVersions, _ := diffVersions(cur, base)
		removedVersions, _ := diffVersions(base, cur)

		switch {
		case len(addedVersions) == 1 && len(removedVersions) == 1:
			// Exactly one version moved: a genuine upgrade or downgrade.
			d.Changed = append(d.Changed, Change{
				Name:        id.name,
				Type:        id.typ,
				FromVersion: removedVersions[0].Version,
				ToVersion:   addedVersions[0].Version,
				PURL:        addedVersions[0].PURL,
			})
		default:
			d.Added = append(d.Added, addedVersions...)
			d.Removed = append(d.Removed, removedVersions...)
		}
	}

	// Identities that vanished entirely.
	for id, base := range baselineByID {
		if _, still := currentByID[id]; !still {
			d.Removed = append(d.Removed, base...)
		}
	}

	sort.SliceStable(d.Added, func(i, j int) bool { return Less(d.Added[i], d.Added[j]) })
	sort.SliceStable(d.Removed, func(i, j int) bool { return Less(d.Removed[i], d.Removed[j]) })
	sort.SliceStable(d.Changed, func(i, j int) bool {
		if d.Changed[i].Type != d.Changed[j].Type {
			return d.Changed[i].Type < d.Changed[j].Type
		}
		return d.Changed[i].Name < d.Changed[j].Name
	})
	return d
}

// groupByIdentity buckets components by (Name, Type), keeping every version.
func groupByIdentity(components []Component) map[identity][]Component {
	out := make(map[identity][]Component, len(components))
	for _, c := range components {
		id := c.identity()
		out[id] = append(out[id], c)
	}
	return out
}

// diffVersions returns the members of a whose Version does not appear in b.
func diffVersions(a, b []Component) (only []Component, matched int) {
	inB := make(map[string]int, len(b))
	for _, c := range b {
		inB[c.Version]++
	}
	for _, c := range a {
		if inB[c.Version] > 0 {
			inB[c.Version]--
			matched++
			continue
		}
		only = append(only, c)
	}
	return only, matched
}

// Tag marks each component in the current inventory with how it differs from
// the baseline, leaving unchanged components with an empty Change.
//
// Tagging is keyed on (Name, Type, Version), not just identity, because an
// identity can hold several versions at once and only some of them may have
// moved.
//
// This is what makes a plain --since run useful: the file keeps the complete
// inventory *and* a consumer can filter it to just what moved, without having
// to join against the delta block by hand. --delta-only uses DeltaComponents
// instead, which drops the unchanged entries entirely.
func (d *Delta) Tag(components []Component) {
	if d == nil {
		return
	}
	type versioned struct {
		id      identity
		version string
	}
	kind := make(map[versioned]string, len(d.Added)+len(d.Changed))
	for _, c := range d.Added {
		kind[versioned{c.identity(), c.Version}] = ChangeAdded
	}
	for _, ch := range d.Changed {
		kind[versioned{identity{ch.Name, ch.Type}, ch.ToVersion}] = ChangeChanged
	}
	for i := range components {
		if k, ok := kind[versioned{components[i].identity(), components[i].Version}]; ok {
			components[i].Change = k
		}
	}
}

// DeltaComponents flattens a Delta into a component list with Change set on
// each entry, for --delta-only output. Removed components keep the version
// they had in the baseline. Unchanged components are omitted entirely.
func (d *Delta) DeltaComponents(current []Component) []Component {
	if d == nil {
		return []Component{}
	}
	type versioned struct {
		id      identity
		version string
	}
	byVersion := make(map[versioned]Component, len(current))
	for _, c := range current {
		byVersion[versioned{c.identity(), c.Version}] = c
	}

	out := make([]Component, 0, len(d.Added)+len(d.Removed)+len(d.Changed))
	for _, c := range d.Added {
		c.Change = ChangeAdded
		out = append(out, c)
	}
	for _, c := range d.Removed {
		c.Change = ChangeRemoved
		out = append(out, c)
	}
	for _, ch := range d.Changed {
		c, ok := byVersion[versioned{identity{ch.Name, ch.Type}, ch.ToVersion}]
		if !ok {
			c = Component{Name: ch.Name, Type: ch.Type, Version: ch.ToVersion, PURL: ch.PURL}
		}
		c.Change = ChangeChanged
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return Less(out[i], out[j]) })
	return out
}

// IsEmpty reports whether nothing changed between the two scans.
func (d *Delta) IsEmpty() bool {
	return d == nil || (len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0)
}

// key is the deduplication tuple. Syft can legitimately report the same
// package from two catalogers; those reports are the same component.
type key struct {
	name    string
	version string
	typ     string
	purl    string
}

func (c Component) key() key {
	return key{c.Name, c.Version, c.Type, c.PURL}
}

// Normalize deduplicates components on (Name, Version, Type, PURL), unions the
// multi-valued fields of merged duplicates, sorts every string slice, and sorts
// the result deterministically.
//
// Two runs against an unchanged machine must produce byte-identical output
// apart from the ScanMeta timestamps; this function is what guarantees that.
func Normalize(components []Component) []Component {
	if len(components) == 0 {
		// Distinguish "no components" from nil so the JSON encoder emits [].
		return []Component{}
	}

	// Preserve first-seen order of keys so the merge result is independent of
	// map iteration order, then sort explicitly at the end.
	order := make([]key, 0, len(components))
	merged := make(map[key]*Component, len(components))

	for _, c := range components {
		k := c.key()
		existing, ok := merged[k]
		if !ok {
			dup := c
			dup.CPEs = append([]string(nil), c.CPEs...)
			dup.Licenses = append([]string(nil), c.Licenses...)
			dup.Locations = append([]string(nil), c.Locations...)
			merged[k] = &dup
			order = append(order, k)
			continue
		}
		existing.CPEs = append(existing.CPEs, c.CPEs...)
		existing.Licenses = append(existing.Licenses, c.Licenses...)
		existing.Locations = append(existing.Locations, c.Locations...)
		// Language and FoundBy are single-valued. Keep the first non-empty so
		// the result does not depend on cataloger completion order.
		if existing.Language == "" {
			existing.Language = c.Language
		}
		if existing.FoundBy == "" {
			existing.FoundBy = c.FoundBy
		}
		if existing.SHA256 == "" {
			existing.SHA256 = c.SHA256
		}
	}

	out := make([]Component, 0, len(order))
	for _, k := range order {
		c := merged[k]
		c.CPEs = SortedSet(c.CPEs)
		c.Licenses = SortedSet(c.Licenses)
		c.Locations = SortedSet(c.Locations)
		out = append(out, *c)
	}

	sort.SliceStable(out, func(i, j int) bool {
		return Less(out[i], out[j])
	})
	return out
}

// Less orders components by Type, then Name, then Version, then PURL.
func Less(a, b Component) bool {
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	return a.PURL < b.PURL
}

// SortedSet returns the input deduplicated, sorted, and stripped of empty
// strings. It returns nil for an empty result so the field is omitted from
// JSON rather than emitted as [].
func SortedSet(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// Normalize sorts the host's multi-valued fields so repeated runs match.
func (h *Host) Normalize() {
	h.IPv4 = SortedSet(h.IPv4)
	h.IPv6 = SortedSet(h.IPv6)
	h.MACs = SortedSet(h.MACs)
}

// AddWarning appends a warning, ignoring blanks and exact duplicates.
func (s *ScanMeta) AddWarning(format string) {
	format = strings.TrimSpace(format)
	if format == "" {
		return
	}
	for _, existing := range s.Warnings {
		if existing == format {
			return
		}
	}
	s.Warnings = append(s.Warnings, format)
}
