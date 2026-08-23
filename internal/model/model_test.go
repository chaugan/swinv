package model

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func TestSortedSet(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"all blank", []string{"", "", ""}, nil},
		{"sorts", []string{"c", "a", "b"}, []string{"a", "b", "c"}},
		{"dedups", []string{"b", "a", "b", "a"}, []string{"a", "b"}},
		{"drops blanks", []string{"b", "", "a"}, []string{"a", "b"}},
		{"already sorted", []string{"a", "b"}, []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SortedSet(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SortedSet(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestSortedSetDoesNotAliasInput guards against the merge logic handing back a
// slice that shares storage with a caller's data.
func TestSortedSetDoesNotAliasInput(t *testing.T) {
	in := []string{"b", "a"}
	got := SortedSet(in)
	got[0] = "mutated"
	if in[0] != "b" || in[1] != "a" {
		t.Errorf("SortedSet result aliases its input: input is now %v", in)
	}
}

func TestNormalizeEmpty(t *testing.T) {
	got := Normalize(nil)
	if got == nil {
		t.Fatal("Normalize(nil) returned nil; want an empty slice so JSON encodes []")
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}

	// The distinction matters at the JSON layer, so assert it there too.
	raw, err := json.Marshal(map[string]any{"components": got})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"components":[]`) {
		t.Errorf("empty components encoded as %s, want []", raw)
	}
}

// TestNormalizeDeduplicatesAndUnions is the core merge contract: the same
// package reported by two catalogers is one component whose multi-valued
// fields are the union of both reports.
func TestNormalizeDeduplicatesAndUnions(t *testing.T) {
	in := []Component{
		{
			Name: "openssl", Version: "3.0.1", Type: "deb", PURL: "pkg:deb/openssl@3.0.1",
			CPEs:      []string{"cpe:b"},
			Licenses:  []string{"Apache-2.0"},
			Locations: []string{"/var/lib/dpkg/status"},
			FoundBy:   "dpkg-db-cataloger",
		},
		{
			Name: "openssl", Version: "3.0.1", Type: "deb", PURL: "pkg:deb/openssl@3.0.1",
			CPEs:      []string{"cpe:a", "cpe:b"},
			Licenses:  []string{"Apache-2.0", "MIT"},
			Locations: []string{"/usr/bin/openssl"},
			FoundBy:   "elf-binary-package-cataloger",
		},
	}

	got := Normalize(in)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1 merged component: %+v", len(got), got)
	}
	c := got[0]
	if want := []string{"cpe:a", "cpe:b"}; !reflect.DeepEqual(c.CPEs, want) {
		t.Errorf("CPEs = %v, want %v", c.CPEs, want)
	}
	if want := []string{"Apache-2.0", "MIT"}; !reflect.DeepEqual(c.Licenses, want) {
		t.Errorf("Licenses = %v, want %v", c.Licenses, want)
	}
	if want := []string{"/usr/bin/openssl", "/var/lib/dpkg/status"}; !reflect.DeepEqual(c.Locations, want) {
		t.Errorf("Locations = %v, want %v", c.Locations, want)
	}
	// FoundBy is single-valued: the first non-empty report wins, so the result
	// does not depend on cataloger completion order.
	if c.FoundBy != "dpkg-db-cataloger" {
		t.Errorf("FoundBy = %q, want the first non-empty value", c.FoundBy)
	}
}

// TestNormalizeKeyIsFullTuple: components differing in any key field stay separate.
func TestNormalizeKeyIsFullTuple(t *testing.T) {
	base := Component{Name: "a", Version: "1", Type: "deb", PURL: "pkg:deb/a@1"}
	variants := []Component{
		base,
		{Name: "b", Version: "1", Type: "deb", PURL: "pkg:deb/a@1"},
		{Name: "a", Version: "2", Type: "deb", PURL: "pkg:deb/a@1"},
		{Name: "a", Version: "1", Type: "rpm", PURL: "pkg:deb/a@1"},
		{Name: "a", Version: "1", Type: "deb", PURL: "pkg:deb/a@2"},
	}
	if got := Normalize(variants); len(got) != len(variants) {
		t.Errorf("len = %d, want %d - components differing in a key field were merged", len(got), len(variants))
	}
}

// TestNormalizeSortOrder pins the documented ordering: type, name, version, purl.
func TestNormalizeSortOrder(t *testing.T) {
	in := []Component{
		{Name: "zlib", Version: "1", Type: "python", PURL: "p3"},
		{Name: "bash", Version: "2", Type: "deb", PURL: "p2"},
		{Name: "bash", Version: "1", Type: "deb", PURL: "p1"},
		{Name: "acl", Version: "1", Type: "deb", PURL: "p0"},
		{Name: "acl", Version: "1", Type: "deb", PURL: "p0a"},
	}
	got := Normalize(in)
	want := []string{"deb/acl/1/p0", "deb/acl/1/p0a", "deb/bash/1/p1", "deb/bash/2/p2", "python/zlib/1/p3"}
	var gotKeys []string
	for _, c := range got {
		gotKeys = append(gotKeys, strings.Join([]string{c.Type, c.Name, c.Version, c.PURL}, "/"))
	}
	if !reflect.DeepEqual(gotKeys, want) {
		t.Errorf("order = %v, want %v", gotKeys, want)
	}
}

// TestNormalizeIsOrderIndependent is the determinism guarantee: the same set of
// components in any input order must normalize to exactly the same output.
// This is what makes two runs on an unchanged machine byte-identical.
func TestNormalizeIsOrderIndependent(t *testing.T) {
	base := []Component{
		{Name: "zlib", Version: "1", Type: "python", CPEs: []string{"c2", "c1"}, Locations: []string{"/b", "/a"}},
		{Name: "bash", Version: "2", Type: "deb", Licenses: []string{"GPL-3.0"}},
		{Name: "acl", Version: "1", Type: "deb", PURL: "pkg:deb/acl@1"},
		{Name: "left-pad", Version: "1.3.0", Type: "npm", Language: "javascript"},
		// A duplicate pair that must merge regardless of where it lands.
		{Name: "acl", Version: "1", Type: "deb", PURL: "pkg:deb/acl@1", Locations: []string{"/usr/bin/acl"}},
	}

	want := Normalize(append([]Component(nil), base...))

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 50; i++ {
		shuffled := append([]Component(nil), base...)
		rng.Shuffle(len(shuffled), func(a, b int) {
			shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
		})
		got := Normalize(shuffled)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("shuffle %d produced a different result:\n got %+v\nwant %+v", i, got, want)
		}
	}
}

// TestNormalizeDoesNotMutateInput: callers keep their slice intact.
func TestNormalizeDoesNotMutateInput(t *testing.T) {
	in := []Component{
		{Name: "a", Version: "1", Type: "deb", CPEs: []string{"z", "a"}},
		{Name: "a", Version: "1", Type: "deb", CPEs: []string{"m"}},
	}
	before := []string{"z", "a"}
	Normalize(in)
	if !reflect.DeepEqual(in[0].CPEs, before) {
		t.Errorf("Normalize mutated its input: CPEs are now %v, want %v", in[0].CPEs, before)
	}
}

func TestLess(t *testing.T) {
	tests := []struct {
		name string
		a, b Component
		want bool
	}{
		{"type first", Component{Type: "deb"}, Component{Type: "npm"}, true},
		{"name second", Component{Type: "deb", Name: "a"}, Component{Type: "deb", Name: "b"}, true},
		{"version third", Component{Type: "deb", Name: "a", Version: "1"}, Component{Type: "deb", Name: "a", Version: "2"}, true},
		{"purl last", Component{Type: "deb", Name: "a", Version: "1", PURL: "x"}, Component{Type: "deb", Name: "a", Version: "1", PURL: "y"}, true},
		{"equal is not less", Component{Type: "deb"}, Component{Type: "deb"}, false},
		{"reversed", Component{Type: "npm"}, Component{Type: "deb"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Less(tt.a, tt.b); got != tt.want {
				t.Errorf("Less = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHostNormalize(t *testing.T) {
	h := Host{
		IPv4: []string{"10.0.0.2", "10.0.0.1", "10.0.0.1"},
		IPv6: []string{"::2", "::1"},
		MACs: []string{"bb:bb", "aa:aa", ""},
	}
	h.Normalize()
	if want := []string{"10.0.0.1", "10.0.0.2"}; !reflect.DeepEqual(h.IPv4, want) {
		t.Errorf("IPv4 = %v, want %v", h.IPv4, want)
	}
	if want := []string{"::1", "::2"}; !reflect.DeepEqual(h.IPv6, want) {
		t.Errorf("IPv6 = %v, want %v", h.IPv6, want)
	}
	if want := []string{"aa:aa", "bb:bb"}; !reflect.DeepEqual(h.MACs, want) {
		t.Errorf("MACs = %v, want %v", h.MACs, want)
	}
}

func TestAddWarning(t *testing.T) {
	var s ScanMeta
	s.AddWarning("first")
	s.AddWarning("first")    // exact duplicate, ignored
	s.AddWarning("  first ") // trims to a duplicate, ignored
	s.AddWarning("")         // blank, ignored
	s.AddWarning("   ")      // whitespace only, ignored
	s.AddWarning("second")

	want := []string{"first", "second"}
	if !reflect.DeepEqual(s.Warnings, want) {
		t.Errorf("Warnings = %v, want %v", s.Warnings, want)
	}
}

// TestSchemaVersionIsSet is a tripwire: the version must never be blank, since
// consumers key their parsing off it.
func TestSchemaVersionIsSet(t *testing.T) {
	if SchemaVersion == "" {
		t.Fatal("SchemaVersion is empty")
	}
}

// TestJSONFieldNames pins the wire format. A rename here breaks every consumer,
// so it should require deliberately editing this test.
func TestJSONFieldNames(t *testing.T) {
	raw, err := json.Marshal(Report{
		SchemaVersion: SchemaVersion,
		Components:    []Component{{Name: "a", Version: "1", Type: "deb"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"schema_version"`, `"tool"`, `"host"`, `"scan"`, `"components"`,
		`"name"`, `"version"`, `"type"`,
	} {
		if !strings.Contains(string(raw), field) {
			t.Errorf("missing JSON field %s in %s", field, raw)
		}
	}
	// Optional fields must be omitted when empty, not emitted as null.
	for _, field := range []string{`"language"`, `"purl"`, `"cpes"`, `"licenses"`, `"locations"`, `"found_by"`} {
		if strings.Contains(string(raw), field) {
			t.Errorf("empty optional field %s should have been omitted", field)
		}
	}
}

// --- delta ------------------------------------------------------------------

func TestComputeDelta(t *testing.T) {
	baseline := Normalize([]Component{
		{Name: "bash", Version: "5.2", Type: "deb"},
		{Name: "openssl", Version: "3.0.11", Type: "deb"},
		{Name: "zlib1g", Version: "1.2.13", Type: "deb"},
		{Name: "flask", Version: "3.0.0", Type: "python"},
	})
	current := Normalize([]Component{
		{Name: "bash", Version: "5.2", Type: "deb"},       // unchanged
		{Name: "openssl", Version: "3.0.14", Type: "deb"}, // changed
		{Name: "curl", Version: "7.88", Type: "deb"},      // added
		{Name: "flask", Version: "3.0.0", Type: "python"}, // unchanged
	})

	d := ComputeDelta(current, baseline)

	if got := names(d.Added); !reflect.DeepEqual(got, []string{"curl"}) {
		t.Errorf("Added = %v, want [curl]", got)
	}
	if got := names(d.Removed); !reflect.DeepEqual(got, []string{"zlib1g"}) {
		t.Errorf("Removed = %v, want [zlib1g]", got)
	}
	if len(d.Changed) != 1 {
		t.Fatalf("Changed = %+v, want exactly one entry", d.Changed)
	}
	ch := d.Changed[0]
	if ch.Name != "openssl" || ch.FromVersion != "3.0.11" || ch.ToVersion != "3.0.14" {
		t.Errorf("Changed[0] = %+v, want openssl 3.0.11 -> 3.0.14", ch)
	}
}

// TestComputeDeltaVersionMoveIsNotAddPlusRemove is the whole point of the
// feature: a package that was upgraded must read as one change, not as a
// removal and an unrelated addition.
func TestComputeDeltaVersionMoveIsNotAddPlusRemove(t *testing.T) {
	d := ComputeDelta(
		[]Component{{Name: "openssl", Version: "3.0.14", Type: "deb"}},
		[]Component{{Name: "openssl", Version: "3.0.11", Type: "deb"}},
	)
	if len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Errorf("an upgrade produced Added=%v Removed=%v; want both empty", names(d.Added), names(d.Removed))
	}
	if len(d.Changed) != 1 {
		t.Errorf("Changed = %+v, want one entry", d.Changed)
	}
}

// TestComputeDeltaSameTypeDifferentEcosystem: a name collision across
// ecosystems must not be treated as the same component.
func TestComputeDeltaDistinguishesTypes(t *testing.T) {
	d := ComputeDelta(
		[]Component{{Name: "requests", Version: "2.0", Type: "npm"}},
		[]Component{{Name: "requests", Version: "2.0", Type: "python"}},
	)
	if len(d.Added) != 1 || len(d.Removed) != 1 {
		t.Errorf("same name in two ecosystems should be one add and one remove, got Added=%v Removed=%v",
			names(d.Added), names(d.Removed))
	}
}

func TestComputeDeltaEmptyCases(t *testing.T) {
	same := []Component{{Name: "bash", Version: "5.2", Type: "deb"}}
	if d := ComputeDelta(same, same); !d.IsEmpty() {
		t.Errorf("identical inputs should produce an empty delta, got %+v", d)
	}
	var nilDelta *Delta
	if !nilDelta.IsEmpty() {
		t.Error("a nil Delta must report empty")
	}
	// A first-ever run has no baseline: everything is added.
	d := ComputeDelta(same, nil)
	if len(d.Added) != 1 || len(d.Removed) != 0 {
		t.Errorf("empty baseline should make everything added, got %+v", d)
	}
}

func TestComputeDeltaIsDeterministic(t *testing.T) {
	baseline := []Component{
		{Name: "b", Version: "1", Type: "deb"}, {Name: "a", Version: "1", Type: "deb"},
	}
	current := []Component{
		{Name: "c", Version: "1", Type: "deb"}, {Name: "a", Version: "2", Type: "deb"},
	}
	first := ComputeDelta(current, baseline)
	for i := 0; i < 20; i++ {
		if !reflect.DeepEqual(ComputeDelta(current, baseline), first) {
			t.Fatalf("ComputeDelta is not deterministic (iteration %d)", i)
		}
	}
}

func TestDeltaComponents(t *testing.T) {
	baseline := []Component{
		{Name: "gone", Version: "1", Type: "deb"},
		{Name: "moved", Version: "1", Type: "deb"},
		{Name: "boring", Version: "1", Type: "deb"},
	}
	current := []Component{
		{Name: "moved", Version: "2", Type: "deb"},
		{Name: "new", Version: "1", Type: "deb"},
		{Name: "boring", Version: "1", Type: "deb"}, // present in both, unchanged
	}
	d := ComputeDelta(current, baseline)
	got := d.DeltaComponents(current)

	kinds := map[string]string{}
	for _, c := range got {
		kinds[c.Name] = c.Change
	}
	want := map[string]string{"gone": ChangeRemoved, "moved": ChangeChanged, "new": ChangeAdded}
	if !reflect.DeepEqual(kinds, want) {
		t.Errorf("DeltaComponents = %v, want %v (unchanged components must be omitted)", kinds, want)
	}
	// The changed entry must carry the CURRENT version, not the baseline one.
	for _, c := range got {
		if c.Name == "moved" && c.Version != "2" {
			t.Errorf("changed component version = %q, want the current version 2", c.Version)
		}
	}

	var nilDelta *Delta
	if got := nilDelta.DeltaComponents(current); len(got) != 0 {
		t.Errorf("nil delta should flatten to nothing, got %v", got)
	}
}

func names(cs []Component) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

// TestDeltaTag: a plain --since run keeps the full inventory but marks what
// moved, so a consumer can filter without joining against the delta block.
func TestDeltaTag(t *testing.T) {
	baseline := []Component{
		{Name: "gone", Version: "1", Type: "deb"},
		{Name: "moved", Version: "1", Type: "deb"},
		{Name: "boring", Version: "1", Type: "deb"},
	}
	current := Normalize([]Component{
		{Name: "moved", Version: "2", Type: "deb"},
		{Name: "new", Version: "1", Type: "deb"},
		{Name: "boring", Version: "1", Type: "deb"},
	})

	d := ComputeDelta(current, baseline)
	d.Tag(current)

	got := map[string]string{}
	for _, c := range current {
		got[c.Name] = c.Change
	}
	want := map[string]string{
		"moved":  ChangeChanged,
		"new":    ChangeAdded,
		"boring": ChangeUnchanged, // still present, deliberately untagged
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Tag = %v, want %v", got, want)
	}
	// "gone" is not in the current inventory, so nothing to tag; it lives in
	// Delta.Removed only.
	if len(current) != 3 {
		t.Errorf("Tag must not add or drop components: len = %d, want 3", len(current))
	}

	var nilDelta *Delta
	nilDelta.Tag(current) // must not panic
}

// TestComputeDeltaMultipleVersionsOfOneIdentity is a regression test for a bug
// that would have fired on essentially every Debian host: two kernels are
// normally installed side by side, and keying the baseline on (name, type)
// alone kept only the last one, so an *unchanged* pair was reported as a
// version change every single run.
func TestComputeDeltaMultipleVersionsOfOneIdentity(t *testing.T) {
	both := []Component{
		{Name: "linux-image", Version: "6.8.0-40", Type: "deb"},
		{Name: "linux-image", Version: "6.8.0-45", Type: "deb"},
	}
	if d := ComputeDelta(both, both); !d.IsEmpty() {
		t.Errorf("identical multi-version inventories must produce an empty delta, got %+v", d)
	}

	// Adding a third kernel is an addition, not a change.
	plusOne := append(append([]Component(nil), both...),
		Component{Name: "linux-image", Version: "6.8.0-50", Type: "deb"})
	d := ComputeDelta(plusOne, both)
	if len(d.Added) != 1 || d.Added[0].Version != "6.8.0-50" {
		t.Errorf("Added = %+v, want just 6.8.0-50", d.Added)
	}
	if len(d.Changed) != 0 || len(d.Removed) != 0 {
		t.Errorf("Changed=%+v Removed=%+v, want both empty", d.Changed, d.Removed)
	}

	// Dropping the oldest kernel is a removal, not a change.
	d = ComputeDelta(both[1:], both)
	if len(d.Removed) != 1 || d.Removed[0].Version != "6.8.0-40" {
		t.Errorf("Removed = %+v, want just 6.8.0-40", d.Removed)
	}
	if len(d.Changed) != 0 || len(d.Added) != 0 {
		t.Errorf("Changed=%+v Added=%+v, want both empty", d.Changed, d.Added)
	}

	// A single version moving is still reported as one change.
	d = ComputeDelta(
		[]Component{{Name: "openssl", Version: "3.0.14", Type: "deb"}},
		[]Component{{Name: "openssl", Version: "3.0.11", Type: "deb"}})
	if len(d.Changed) != 1 {
		t.Errorf("a lone version move should be one Changed entry, got %+v", d)
	}
}

// TestTagIsVersionAware: when an identity holds several versions, only the one
// that actually moved may be tagged.
func TestTagIsVersionAware(t *testing.T) {
	baseline := []Component{{Name: "linux-image", Version: "6.8.0-40", Type: "deb"}}
	current := Normalize([]Component{
		{Name: "linux-image", Version: "6.8.0-40", Type: "deb"},
		{Name: "linux-image", Version: "6.8.0-50", Type: "deb"},
	})
	d := ComputeDelta(current, baseline)
	d.Tag(current)

	got := map[string]string{}
	for _, c := range current {
		got[c.Version] = c.Change
	}
	if got["6.8.0-40"] != ChangeUnchanged {
		t.Errorf("the pre-existing kernel was tagged %q, want untagged", got["6.8.0-40"])
	}
	if got["6.8.0-50"] != ChangeAdded {
		t.Errorf("the new kernel was tagged %q, want %q", got["6.8.0-50"], ChangeAdded)
	}
}

// TestNormalizeMergesAttributes pins a silent inaccuracy found on a real
// Windows machine: 135 Appx packages became 119 components because some share
// a name and version and differ only in architecture -- x64 and x86 of the
// same runtime, which is ordinary. Keeping the first component's attributes
// made the merged row claim one architecture while listing both install paths.
func TestNormalizeMergesAttributes(t *testing.T) {
	in := []Component{
		{
			Name: "Microsoft.VCLibs.140.00", Version: "14.0.33519.0", Type: "msix",
			Locations:  []string{`C:\Program Files\WindowsApps\x64`},
			Attributes: map[string]string{"architecture": "x64", "publisher_id": "8wekyb3d8bbwe"},
		},
		{
			Name: "Microsoft.VCLibs.140.00", Version: "14.0.33519.0", Type: "msix",
			Locations:  []string{`C:\Program Files\WindowsApps\x86`},
			Attributes: map[string]string{"architecture": "x86", "publisher_id": "8wekyb3d8bbwe"},
		},
	}

	out := Normalize(in)
	if len(out) != 1 {
		t.Fatalf("got %d components, want 1", len(out))
	}
	if got := out[0].Attributes["architecture"]; got != "x64;x86" {
		t.Errorf("architecture = %q, want %q: both are installed and the row must say so", got, "x64;x86")
	}
	// An attribute both agree on must not be duplicated into a list.
	if got := out[0].Attributes["publisher_id"]; got != "8wekyb3d8bbwe" {
		t.Errorf("publisher_id = %q, want the single shared value", got)
	}
	if len(out[0].Locations) != 2 {
		t.Errorf("locations = %v, want both", out[0].Locations)
	}
}

// TestNormalizeAttributeMergeIsDeterministic: map iteration is not ordered, and
// a report that differs between identical runs cannot be diffed.
func TestNormalizeAttributeMergeIsDeterministic(t *testing.T) {
	build := func() []Component {
		return []Component{
			{Name: "x", Version: "1", Type: "t", Attributes: map[string]string{"a": "3"}},
			{Name: "x", Version: "1", Type: "t", Attributes: map[string]string{"a": "1"}},
			{Name: "x", Version: "1", Type: "t", Attributes: map[string]string{"a": "2"}},
		}
	}
	first := Normalize(build())[0].Attributes["a"]
	if first != "1;2;3" {
		t.Errorf("a = %q, want sorted %q", first, "1;2;3")
	}
	for i := 0; i < 20; i++ {
		if got := Normalize(build())[0].Attributes["a"]; got != first {
			t.Fatalf("run %d gave %q, first run gave %q", i, got, first)
		}
	}
}

// TestNormalizeDoesNotMutateItsInput: the merge writes into a map, and writing
// into the caller's would corrupt a component list the caller still holds.
func TestNormalizeDoesNotMutateItsInput(t *testing.T) {
	original := map[string]string{"architecture": "x64"}
	in := []Component{
		{Name: "x", Version: "1", Type: "t", Attributes: original},
		{Name: "x", Version: "1", Type: "t", Attributes: map[string]string{"architecture": "x86"}},
	}

	Normalize(in)

	if got := original["architecture"]; got != "x64" {
		t.Errorf("input attribute was mutated to %q", got)
	}
}
