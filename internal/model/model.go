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
const SchemaVersion = "1.6"

// Report is the top-level document written as JSON.
type Report struct {
	SchemaVersion string      `json:"schema_version"`
	Tool          Tool        `json:"tool"`
	Host          Host        `json:"host"`
	Scan          ScanMeta    `json:"scan"`
	Delta         *Delta      `json:"delta,omitempty"`
	Components    []Component `json:"components"`

	// Services are what is listening on this machine, and which installed
	// software is behind it.
	//
	// A relation rather than a property of a component: one nginx backs many
	// sites, and one service involves the daemon, the libraries it loaded and
	// the application it serves. A "role" field on Component would collapse a
	// many-to-many reality into a one-to-one lie.
	//
	// Software that appears here always also appears in Components. A consumer
	// that ignores this array loses context and loses nothing else -- which
	// matters because most vulnerability matchers do ignore it.
	Services []Service `json:"services,omitempty"`
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
	Name string `json:"name"`

	// Version is omitted when a cataloger could not determine one, rather than
	// emitted as "" or as a placeholder.
	//
	// Syft writes "UNKNOWN" in that case, and unlike an absent field that is
	// dangerous rather than untidy: it is valid syntax in several version
	// grammars, and under Debian ordering it has no epoch, so it sorts below
	// every real release. A consumer asking "is the installed version below
	// the fixed version" gets yes, for every advisory ever filed against that
	// package. A downstream matcher reported exactly that against git in a
	// snap base. An absent field cannot be compared by accident.
	Version  string `json:"version,omitempty"`
	Type     string `json:"type"`
	Language string `json:"language,omitempty"`

	// Vendor is the organisation behind the component, as its own ecosystem
	// records it: an rpm Vendor, a dpkg or apk Maintainer, or CompanyName from
	// a Windows PE version resource. Those are related but not identical
	// facts, and the raw value is kept rather than normalised — see
	// vendorFromPackage in internal/scan.
	//
	// Frequently empty. Many ecosystems record no such field at all.
	Vendor string `json:"vendor,omitempty"`

	// OwnedBy is the PURL of the OS package that owns this component's files,
	// when one does.
	//
	// A distribution-installed language package is reported twice, correctly:
	// once as the OS package the vendor patches, once as the ecosystem package
	// upstream advisories are written against. Both rows are right and neither
	// should be dropped. But without a link between them, a consumer assessing
	// the second as an upstream release compares a backported version against
	// upstream's — Ubuntu's python3-cryptography 2.1.4-1ubuntu1.4+esm1 is
	// patched, while PyPI's cryptography 2.1.4 looks thirty-seven releases
	// behind. On one reported host that produced 442 false findings.
	//
	// Empty when nothing owns the files, which is the normal case for anything
	// installed by pip, npm or a virtualenv rather than by the distribution --
	// and those genuinely should be assessed against upstream. Also empty when
	// --no-file-ownership was passed, since that is the computation this comes
	// from.
	OwnedBy string `json:"owned_by,omitempty"`

	// Root is the filesystem root this component was found in: "/" for the
	// scanned machine, or the path of a nested root such as a snap base or a
	// container layer.
	//
	// It is part of a component's identity, not decoration. Two packages with
	// the same name and version in two different roots are two installs with
	// two patch states, and merging them loses that -- along with the evidence
	// of which root each belongs to, which is what decides whose advisories
	// apply.
	Root string `json:"root,omitempty"`

	// Attributes carries ecosystem-specific identity that does not deserve a
	// column of its own: a Windows product code or registry key, an MSIX
	// package family name, an install scope.
	//
	// A map rather than more fields, because the alternative is a Component
	// struct that grows a field per platform and is mostly empty on every one
	// of them. Deliberately absent from the CSV, whose fixed column shape is
	// what lets files be concatenated across machines; JSON and CycloneDX
	// carry it.
	//
	// Keys are lowercase and underscore-separated. Empty values are dropped
	// rather than written, so a key being present means something was recorded.
	Attributes map[string]string `json:"attributes,omitempty"`
	PURL       string            `json:"purl,omitempty"`
	CPEs       []string          `json:"cpes,omitempty"`
	Licenses   []string          `json:"licenses,omitempty"`
	Locations  []string          `json:"locations,omitempty"`
	FoundBy    string            `json:"found_by,omitempty"`

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
	// root keeps components from different filesystem roots apart. Two
	// packages of the same name and version in a snap base and on the host are
	// two installs with two patch states; merging them also merged their
	// locations, so a consumer could no longer tell which root either came
	// from -- and that is what decides whose advisories apply.
	root string
}

func (c Component) key() key {
	return key{c.Name, c.Version, c.Type, c.PURL, c.Root}
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
			dup.Attributes = copyAttributes(c.Attributes)
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
		if existing.Vendor == "" {
			existing.Vendor = c.Vendor
		}
		if existing.OwnedBy == "" {
			existing.OwnedBy = c.OwnedBy
		}
		existing.Attributes = mergeAttributes(existing.Attributes, c.Attributes)
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

// copyAttributes returns an independent copy, so merging into one component
// cannot mutate the map another still holds.
func copyAttributes(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// mergeAttributes combines the attributes of two components being deduplicated.
//
// Keeping only the first component's map is the obvious implementation and is
// quietly wrong. Two Appx packages can share a name and version and differ in
// architecture -- x64 and x86 of the same runtime, which is ordinary on
// Windows -- and the merged row then claims one architecture while listing
// both install paths. That reads as a fact and is half of one.
//
// Conflicting values are joined with ";", the same convention the CSV uses for
// multi-valued fields, so "x64;x86" says what is actually installed. Values
// are sorted, because map iteration is not, and a report that changes between
// identical runs is not comparable.
func mergeAttributes(a, b map[string]string) map[string]string {
	if len(b) == 0 {
		return a
	}
	if a == nil {
		a = make(map[string]string, len(b))
	}

	for k, v := range b {
		switch existing := a[k]; existing {
		case "":
			a[k] = v
		case v:
			// Same fact twice.
		default:
			values := append(strings.Split(existing, ";"), v)
			a[k] = strings.Join(SortedSet(values), ";")
		}
	}
	return a
}

// Identify names a component the way a consumer joins on it: its PURL where
// one exists, and "name@version" otherwise -- which is the case for Windows
// registry entries and for anything a cataloger could not give a canonical
// identifier.
//
// It lives here rather than beside its callers because two of them have to
// agree exactly: the service attribution that writes these strings into
// Service.Components, and the CycloneDX writer that resolves them back to
// bom-refs. A second, subtly different spelling in either place would produce
// a document whose dependency graph silently points at nothing.
func Identify(c Component) string {
	if c.PURL != "" {
		return c.PURL
	}
	if c.Version != "" {
		return c.Name + "@" + c.Version
	}
	return c.Name
}

// Confidence is how firmly a service is attributed to software.
//
// Recorded rather than implied, because a service finding is assembled from
// evidence of varying strength and a consumer cannot tell the difference by
// looking. A single field claiming "port 443 is nginx 1.24" is
// indistinguishable from a guess by the time it reaches anyone.
type Confidence string

const (
	// ConfidenceHigh: the listening process was identified and its executable
	// belongs to a package in the inventory.
	ConfidenceHigh Confidence = "high"

	// ConfidenceMedium: the process was identified but nothing installed owns
	// its executable. Not a weaker observation -- it is the interesting one,
	// since software running outside package management is what an inventory
	// cannot otherwise see -- but the product and version are unknown.
	ConfidenceMedium Confidence = "medium"

	// ConfidenceLow: something is listening and the process behind it could not
	// be identified, because the scan lacked the privilege to read another
	// user's open files, or because init holds the socket.
	ConfidenceLow Confidence = "low"
)

// Service is one listening process and what is known about it.
type Service struct {
	// Endpoints are what it accepts on, as "0.0.0.0:443/tcp".
	Endpoints []string `json:"endpoints"`

	PID int `json:"pid,omitempty"`

	// Executable is the path as it exists in the process's own mount
	// namespace, which for a containerised process need not exist on the host.
	Executable string `json:"executable,omitempty"`

	// Command is the process's argv.
	//
	// It is the only identification available for an interpreted daemon, where
	// the executable names the runtime -- java, python, node -- and the
	// application is named in the arguments. It may also contain a secret
	// passed on a command line, which is why --no-service-command exists and
	// why SECURITY.md says so plainly.
	Command string `json:"command,omitempty"`

	// Unit is the owning systemd unit; Container the container id, when the
	// process runs in one.
	Unit      string `json:"unit,omitempty"`
	Container string `json:"container,omitempty"`

	// User is the numeric uid the process runs as.
	User string `json:"user,omitempty"`

	// SocketActivated marks a socket held by init rather than by the service
	// that will answer on it. The daemon may not be running at all.
	SocketActivated bool `json:"socket_activated,omitempty"`

	// Components identifies the installed software behind this service, by
	// PURL where one exists and by "name@version" otherwise. Empty means
	// nothing installed owns the executable.
	Components []string `json:"components,omitempty"`

	Confidence Confidence `json:"confidence"`

	// Evidence records what produced this finding, in the order it was
	// established. A consumer that disagrees with the conclusion can see what
	// it rests on.
	Evidence []string `json:"evidence,omitempty"`
}
