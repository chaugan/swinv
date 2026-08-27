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
// 1.10 added ScanMeta.ScanID and ScanMeta.Sources, which are the self-
// describing manifest (see the NDJSON heartbeat record). Also additive.
const SchemaVersion = "1.14"

// Report is the top-level document written as JSON.
type Report struct {
	SchemaVersion string      `json:"schema_version"`
	Tool          Tool        `json:"tool"`
	Host          Host        `json:"host"`
	Scan          ScanMeta    `json:"scan"`
	Delta         *Delta      `json:"delta,omitempty"`
	Components    []Component `json:"components"`

	// NDJSONInclude names the extra record types the NDJSON stream should
	// carry beyond components, from --ndjson-include.
	//
	// It rides on the report because the writers take nothing but a report,
	// and it is a statement about this run rather than about the machine --
	// which is why it never appears in any output document.
	NDJSONInclude []string `json:"-"`

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

	// Containers are the containerised workloads found on this machine and what
	// each is listening on *inside its own network namespace*.
	//
	// Separate from Services and from Exposure because it answers a separate
	// question -- what is running in the containers, with an identity a
	// vulnerability matcher can use -- and because nothing in here is a claim
	// about host reachability. A container port reaches the host only if
	// something published it, and that fact lives in Exposure, cross-linked
	// from Service.PublishedAs.
	Containers []Container `json:"containers,omitempty"`

	// Links maps every probed executable to the shared libraries it loads.
	// Filled only with --elf-scope all; the default scope attaches links to
	// the listening services instead, where the exposure question is asked.
	Links []BinaryLinks `json:"links,omitempty"`

	// ConfigSurface is the host's persistence and privilege configuration:
	// cron jobs, systemd timers and services, SUID binaries, scheduled tasks
	// and autoruns. See ConfigEntry.
	ConfigSurface []ConfigEntry `json:"config_surface,omitempty"`

	// Exposure is every listening socket in the *host* network namespace, and
	// nothing else.
	//
	// Membership is the verdict. A socket bound to 0.0.0.0 inside a
	// container's network namespace is not reachable on this host, and if such
	// a row appeared here alongside an address a reader would draw the
	// opposite conclusion -- so those rows are not here at all, and a consumer
	// reading only this array cannot get it wrong. BindScope then says how
	// widely each of these is bound.
	//
	// It is a separate array rather than a view of Services because for a
	// forwarded port the two carry different facts: docker-proxy holds the
	// socket, and the software worth naming is inside the container behind it.
	Exposure []Exposure `json:"exposure,omitempty"`
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

	// InventoryDigest fingerprints the component list, for a consumer deciding
	// whether this host changed without reading every component of it.
	//
	// Only set with --heartbeat. Empty means it was not computed, which is not
	// the same as an empty inventory.
	InventoryDigest string `json:"inventory_digest,omitempty"`

	// InventoryUnchanged is true when that digest matches the previous scan's
	// on this host.
	//
	// It is what lets the NDJSON stream carry a heartbeat instead of fourteen
	// thousand component records that say exactly what the last fourteen
	// thousand said. Never set without --heartbeat, and never a reason for any
	// other format to omit anything: a CSV with no rows would be a false
	// statement about the machine, where a heartbeat is a true one.
	InventoryUnchanged bool `json:"inventory_unchanged,omitempty"`

	// FirewallExamined is always false, and is emitted anyway.
	//
	// A constant costs a few bytes and is the entire difference between "no
	// firewall rules were found" and "firewall rules were never read" for a
	// consumer building an exposure report. Putting the disclaimer in the
	// document rather than only in the documentation is what makes it reach
	// the ingest pipeline, which drops prose.
	FirewallExamined bool `json:"firewall_examined"`

	// ScanID identifies this run, and only this run.
	//
	// It is the idempotency key for transmission: every batch of this scan
	// carries it, so a retry after a timeout cannot double-count a host, and a
	// collector that died half way through can name what it was uploading and
	// resume it. Written into the manifest record so the same identifier
	// appears in the file an air-gapped site carries by hand.
	ScanID string `json:"scan_id,omitempty"`

	// Sources says what each enumeration source did: read, skipped, or failed.
	//
	// Components here counts what the source contributed to this scan's
	// inventory. That is not always what the NDJSON stream carries: with
	// --heartbeat an unchanged host sends no component records at all, so the
	// manifest's counts drop to zero while these stay at what was found. The
	// manifest carries inventory_unchanged so the receiver can tell the two
	// cases apart instead of guessing.
	//
	// Empty means the sources were never determined, which is not the same as
	// a machine with no sources.
	Sources map[string]SourceStatus `json:"sources,omitempty"`

	// ExposureBlindSpots names, in machine-readable form, the classes of
	// exposure this scan could not observe.
	//
	// The most important field in the exposure section. Without it a host
	// running Docker with userland-proxy disabled -- where publishing is pure
	// netfilter DNAT and no process holds a socket -- produces a document
	// identical to a host with nothing exposed at all. A consumer must be able
	// to tell "looked and found nothing" from "could not look".
	ExposureBlindSpots []string `json:"exposure_blind_spots,omitempty"`
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
	// facts, and the raw value is kept rather than normalised - see
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
	// upstream's - Ubuntu's python3-cryptography 2.1.4-1ubuntu1.4+esm1 is
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
// addition - which is the whole point of running a delta on a daily inventory.
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

// Link is one shared library a binary loads, joined to the package that
// installed it.
type Link struct {
	// Soname is what the binary asks for: "libcrypto.so.3" on Linux; on
	// Windows the DLL name from the import table, "WS2_32.dll". The field
	// keeps its ELF name because a consumer joins on one field, not two.
	Soname string `json:"soname"`

	// Path is where the dynamic linker finds it, resolved without executing
	// anything. Empty means the library was not found on the filesystem the
	// binary lives in -- which is itself a finding, not a formatting gap.
	Path string `json:"path,omitempty"`

	// PURL identifies the package owning the resolved path. Empty means
	// nothing installed owns it: a vendored or hand-copied library, which for
	// a CVE consumer is the more interesting case, not the less. On Windows
	// it carries the owning product's identity the way services[].components
	// does - a PURL when one exists, "Name@Version" otherwise.
	PURL string `json:"purl,omitempty"`

	// OSComponent marks a library that is part of the operating system - on
	// Windows, a System32 DLL, which the inventory represents by the
	// installed updates rather than file by file. Without this flag every
	// KERNEL32.dll would read as "nothing installed owns it", which is the
	// interesting-case signal pointed at the least interesting files.
	OSComponent bool `json:"os_component,omitempty"`

	// Transitive marks a library reached through another one -- postgres
	// needs libpq, libpq needs libssl -- rather than named by the binary
	// itself. Both matter to "does this service load the vulnerable library",
	// but they are different strengths of statement.
	Transitive bool `json:"transitive,omitempty"`

	// NSymbols counts the named functions the probed binary imports from this
	// library; Symbols lists them (only with --elf-symbols, only for direct
	// links, capped). A symbol list names the API entry points called, not
	// the code that runs: most CVEs live in internal functions that appear in
	// no import table, so "loads the library" is the reliable signal and
	// these are supporting evidence, never a verdict.
	NSymbols         int      `json:"n_symbols,omitempty"`
	Symbols          []string `json:"symbols,omitempty"`
	SymbolsTruncated bool     `json:"symbols_truncated,omitempty"`
}

// BinaryLinks is one executable and what it links, for --elf-scope all --
// every ELF on the machine, not only the listening ones.
type BinaryLinks struct {
	Executable string `json:"executable"`

	// PURL identifies the package owning the executable itself, when one does.
	PURL string `json:"purl,omitempty"`

	Links []Link `json:"links,omitempty"`
}

// ConfigEntry is one element of the host's configuration surface: a
// mechanism that runs code, grants privilege, or persists across reboots.
//
// This is a second class of fact alongside the installed-software inventory,
// and it exists because the techniques that fill an ATT&CK matrix are mostly
// not software defects - they are configurations, and the only honest way to
// reach them is to collect them. Everything here is a local file or registry
// read: no execution, no probing, no network.
//
// Collecting an entry is not a finding. The findings fall out of joins a
// consumer makes against the rest of the report: a root cron job whose
// script is world-writable, a SUID binary no package owns, a unit whose
// ExecStart points outside every package-owned path. The fields carry the
// facts those joins need and no verdicts.
type ConfigEntry struct {
	// Kind is one of the ConfigKind* constants below.
	Kind string `json:"kind"`

	// Name identifies the entry within its kind: the unit file name, the
	// task path, the autorun value name, the crontab line's position.
	Name string `json:"name,omitempty"`

	// Path is the file or registry key the entry was read from.
	Path string `json:"path,omitempty"`

	// User is who the entry runs as, when the mechanism states it.
	User string `json:"user,omitempty"`

	// Schedule is when it runs, in the mechanism's own vocabulary: a cron
	// spec, an OnCalendar expression, "@daily".
	Schedule string `json:"schedule,omitempty"`

	// Command is the full command line. Omitted under --no-service-command,
	// for the same reason that flag exists: command lines carry passwords
	// and tokens, and an inventory file is usually copied somewhere else.
	Command string `json:"command,omitempty"`

	// Executable is the resolved program path, kept even when Command is
	// redacted: a path is joinable and carries no secrets.
	Executable string `json:"executable,omitempty"`

	// PURL identifies the package owning the executable, when one does.
	// An entry with an Executable and no PURL is a mechanism running code
	// nothing installed - for a consumer, the more interesting case.
	PURL string `json:"purl,omitempty"`

	// Attack is the MITRE ATT&CK technique this mechanism is the surface
	// for - the surface, not evidence of use.
	Attack string `json:"attack,omitempty"`

	// Mode is the octal file mode, recorded for suid entries.
	Mode   string `json:"mode,omitempty"`
	SetUID bool   `json:"setuid,omitempty"`
	SetGID bool   `json:"setgid,omitempty"`

	// WorldWritable is set when the executable this entry runs can be
	// rewritten by any local user - the joinable half of "a root cron job
	// anyone can edit".
	WorldWritable bool `json:"world_writable,omitempty"`

	Evidence []string `json:"evidence,omitempty"`
}

// The configuration-surface kinds, each with the ATT&CK technique it maps to.
const (
	ConfigKindCron           = "cron"            // T1053.003
	ConfigKindSystemdTimer   = "systemd-timer"   // T1053.006
	ConfigKindSystemdService = "systemd-service" // T1543.002
	ConfigKindSUID           = "suid"            // T1548.001
	ConfigKindScheduledTask  = "scheduled-task"  // T1053.005
	ConfigKindAutorun        = "autorun"         // T1547.001
)

// BindScope describes how widely a socket is bound. It is a fact about the
// bind, not a claim about reachability: swinv reads no firewall, no NAT table
// and no cloud security group, and a field that implied otherwise would be the
// most dangerous one in the document.
type BindScope string

const (
	// BindWildcard: 0.0.0.0 or ::, so every address the host has now and every
	// one added tomorrow.
	BindWildcard BindScope = "wildcard"

	// BindLoopback: 127.0.0.0/8 or ::1, reachable only from this machine.
	BindLoopback BindScope = "loopback"

	// BindLinkLocal: 169.254.0.0/16 or fe80::/10.
	BindLinkLocal BindScope = "link_local"

	// BindSpecific: one particular address. Deliberately not split into
	// "private" and "public": swinv cannot tell a lab bridge from a flat
	// datacentre L2 where every host reaches every address, and emitting
	// "private" would invite the conclusion that it is therefore safe. The
	// address is in the record; the consumer classifies it against a network
	// model swinv does not have.
	BindSpecific BindScope = "specific"
)

// Backend is what a forwarded host port leads to.
//
// A published container port is held on the host by a forwarding process --
// docker-proxy, rootlessport, pasta -- whose own package is not the answer to
// "what is running here". Recording the forward separately is what lets the
// identity be the software behind it while keeping the fact that a forward was
// involved.
type Backend struct {
	Address string `json:"address,omitempty"`
	Port    uint16 `json:"port,omitempty"`

	// Container is the container id the forward leads to, and Executable the
	// listening executable inside it, when both were resolved.
	Container  string `json:"container,omitempty"`
	Executable string `json:"executable,omitempty"`

	// Via names how the forward was learned, so a consumer can weigh it:
	// "docker-proxy-argv" is the forwarding process's own command line.
	Via string `json:"via,omitempty"`
}

// Image identifies a container image.
//
// Every field here is a **locator, not an identity a vulnerability matcher can
// use**. There is no `oci` matcher in Grype, no OCI coordinates in OSV or OSS
// Index, and Dependency-Track will ingest an image PURL, find nothing, and
// display the component as clean -- which is indistinguishable from "analysed
// and safe". So this never appears in Components. It is here so a consumer can
// join to an image scan it performs elsewhere, which is the thing that
// actually produces findings for an image.
type Image struct {
	// Ref is the image reference as the runtime recorded it, e.g.
	// "splunk/splunk:latest".
	Ref string `json:"ref,omitempty"`

	// ManifestDigest is the "repo@sha256:..." digest, which is what an image
	// scanner elsewhere will have seen, and ID is the local image identifier.
	//
	// Both are reported rather than one, because which is which depends on the
	// daemon: a Docker 29 engine using the containerd image store reported the
	// same sha256 for both on a pulled image, while the same host's on-disk
	// container state carried a different manifest digest for it. A locally
	// built image that was never pushed has no repo digest at all.
	ManifestDigest string `json:"manifest_digest,omitempty"`
	ID             string `json:"id,omitempty"`

	// PURL is the pkg:oci form, for consumers that key on it. A locator, as
	// above.
	PURL string `json:"purl,omitempty"`
}

// Container is one containerised workload and what it runs.
type Container struct {
	// ID is the runtime's container identifier, as it appears in the cgroup.
	ID string `json:"id"`

	// Name is the human name where one could be read; Runtime names the
	// runtime that was identified ("docker", "containerd", "cri-o", "podman").
	Name    string `json:"name,omitempty"`
	Runtime string `json:"runtime,omitempty"`

	// State is the runtime's own word: "running", "exited", "created".
	//
	// A stopped container serves nothing, so it contributes no exposure. It is
	// still software present on the machine, which is a different claim and
	// worth making: an image with a known CVE does not stop having it because
	// the container is down, and it will be up again.
	State string `json:"state,omitempty"`

	// DeclaredEndpoints are the ports the image or the run configuration says
	// this container serves on, as "8080/tcp".
	//
	// A declaration, never an observation. For a stopped container it is the
	// only network fact available, and a consumer must not read it as an open
	// port -- what is actually reachable on this host is in Report.Exposure
	// and nowhere else.
	DeclaredEndpoints []string `json:"declared_endpoints,omitempty"`

	Image *Image `json:"image,omitempty"`

	// OSID and OSVersionID come from the container's own /etc/os-release, read
	// through /proc/<pid>/root. A container is a different operating system
	// from its host -- this one is RHEL 8.10 on an Ubuntu 26.04 machine -- and
	// that is what decides which advisories apply to its packages.
	OSID        string `json:"os_id,omitempty"`
	OSVersionID string `json:"os_version_id,omitempty"`

	// Pod names the Kubernetes pod, when the runtime recorded one. Absent is
	// the normal case, including on Kubernetes when the annotations could not
	// be read; it is never inferred.
	Pod *Pod `json:"pod,omitempty"`

	// Services are what this container is listening on inside its own network
	// namespace. These endpoints carry no host-reachability claim.
	Services []Service `json:"services,omitempty"`
}

// Pod is the Kubernetes identity of a container, read from the runtime's own
// annotations or from the container's filesystem. Never inferred.
type Pod struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	UID       string `json:"uid,omitempty"`
	Container string `json:"container,omitempty"`
}

// Exposure is one listening socket in the host network namespace.
//
// The unit is the socket rather than the process because that is the unit of
// work for the consumer this exists for: the question is "is this port a
// problem", and a process bound to four sockets can be four different answers.
type Exposure struct {
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"` // tcp or udp
	Family   string `json:"family"`   // ipv4 or ipv6

	BindScope BindScope `json:"bind_scope"`

	// WildcardCoversIPv4 marks a "::" bind on a kernel with bindv6only
	// disabled, which accepts IPv4 traffic too. Without it a reader counting
	// IPv4 exposure from the family field alone would undercount.
	WildcardCoversIPv4 bool `json:"wildcard_covers_ipv4,omitempty"`

	PID        int    `json:"pid,omitempty"`
	Executable string `json:"executable,omitempty"`
	Unit       string `json:"unit,omitempty"`
	User       string `json:"user,omitempty"`

	// OSComponent marks an endpoint served by the operating system itself.
	// See Service.OSComponent.
	OSComponent bool `json:"os_component,omitempty"`

	// Processes is how many sockets were found bound to this endpoint, when
	// more than one was. A browser opens twenty on 0.0.0.0:5353 for mDNS, and
	// as exposure that is one open port -- reporting twenty rows for it buried
	// the rest of the list on a real host.
	Processes int `json:"processes,omitempty"`

	// Container is set when the *listening* process is itself containerised,
	// which on the host network namespace means a --network=host container or
	// a hostNetwork pod.
	Container string `json:"container,omitempty"`

	Backend *Backend `json:"backend,omitempty"`
	Image   *Image   `json:"image,omitempty"`

	// Components identifies the software behind this endpoint, by PURL. For a
	// forwarded port this is the package inside the container, never the
	// forwarding process's own package -- naming docker-ce as the software
	// behind a published port is true and useless.
	Components []string `json:"components,omitempty"`

	Confidence Confidence `json:"confidence"`
	Evidence   []string   `json:"evidence,omitempty"`
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

	// OSComponent marks a listener that is part of the operating system
	// itself.
	//
	// It exists because "medium" would otherwise be a lie about it. Medium
	// means the process was identified and nothing installed owns its
	// executable -- software running outside package management, which is the
	// interesting finding. A Windows service running from C:\Windows\System32
	// is the opposite of that: it came with the operating system, which swinv
	// represents by the installed servicing updates rather than file by file.
	// Without this flag a consumer filtering for unmanaged software would
	// collect several dozen of them from every Windows host.
	OSComponent bool `json:"os_component,omitempty"`

	// Processes is how many processes share this listener, when more than one
	// does. A prefork server -- nginx with its workers, php-fpm, gunicorn --
	// is one service on one socket, and reporting it as nine would misstate
	// both what is running and how much of it.
	Processes int `json:"processes,omitempty"`

	// Links are the shared libraries this service's executable loads, each
	// resolved to the installed package that owns it.
	//
	// This is the join that answers "a CVE landed in a common library -- which
	// network-facing services actually load it". A package inventory says
	// openssl is installed; this says sshd, listening on 0.0.0.0:22, loads
	// libcrypto.so.3 from that package. Link-time truth only: dlopen'd
	// modules, PAM and NSS are invisible here, and the evidence says so.
	Links []Link `json:"links,omitempty"`

	// PublishedAs lists the host endpoints that forward to this service, for a
	// service inside a container. Empty means nothing was found publishing it,
	// which is the ordinary case and is not the same as "it is not reachable"
	// -- see ScanMeta.ExposureBlindSpots.
	PublishedAs []string `json:"published_as,omitempty"`
}
