package model

import "testing"

func comps() []Component {
	return []Component{
		{Name: "openssl", Version: "3.0.11", Type: "deb", Root: "/", PURL: "pkg:deb/debian/openssl@3.0.11"},
		{Name: "bash", Version: "5.2.15", Type: "deb", Root: "/", PURL: "pkg:deb/debian/bash@5.2.15"},
	}
}

// Two runs against an unchanged machine must agree, or a fleet reports every
// host as changed on every scan and the whole point is lost.
func TestInventoryDigestIsStable(t *testing.T) {
	// Two separately built lists describing the same machine, which is what
	// two consecutive scans produce.
	first, second := comps(), comps()
	if InventoryDigest(first) != InventoryDigest(second) {
		t.Fatal("the same inventory produced two digests")
	}
	// And it must not depend on the order the catalogers happened to run in.
	reversed := []Component{comps()[1], comps()[0]}
	if InventoryDigest(comps()) != InventoryDigest(reversed) {
		t.Error("the digest changed when the component order did")
	}
}

// Anything that changes what is installed has to move it.
func TestInventoryDigestMovesOnRealChange(t *testing.T) {
	base := InventoryDigest(comps())

	upgraded := comps()
	upgraded[0].Version = "3.0.12"
	if InventoryDigest(upgraded) == base {
		t.Error("a version change did not move the digest")
	}

	added := append(comps(), Component{Name: "curl", Version: "8.5.0", Type: "deb", Root: "/"})
	if InventoryDigest(added) == base {
		t.Error("an added package did not move the digest")
	}

	// Removal is the one a delta cannot express, and the reason the full list
	// is resent rather than a diff.
	removed := comps()[:1]
	if InventoryDigest(removed) == base {
		t.Error("a removed package did not move the digest")
	}

	// A package moving between roots is a different package.
	moved := comps()
	moved[0].Root = "/snap/core22/current"
	if InventoryDigest(moved) == base {
		t.Error("a root change did not move the digest")
	}
}

// And nothing else may move it, or every host reports change constantly and
// the signal is ignored within a week.
func TestInventoryDigestIgnoresVolatileFields(t *testing.T) {
	base := InventoryDigest(comps())

	for name, mutate := range map[string]func(*Component){
		"locations": func(c *Component) { c.Locations = []string{"/usr/bin/x", "/usr/bin/y"} },
		"found_by":  func(c *Component) { c.FoundBy = "some-renamed-cataloger" },
		"sha256":    func(c *Component) { c.SHA256 = "deadbeef" },
		"change":    func(c *Component) { c.Change = "added" },
		"licenses":  func(c *Component) { c.Licenses = []string{"MIT"} },
		"cpes":      func(c *Component) { c.CPEs = []string{"cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"} },
		"vendor":    func(c *Component) { c.Vendor = "Someone" },
	} {
		mutated := comps()
		mutate(&mutated[0])
		if InventoryDigest(mutated) != base {
			t.Errorf("%s moved the digest; it does not say a package was installed or removed", name)
		}
	}
}

func TestInventoryDigestOfNothing(t *testing.T) {
	empty := InventoryDigest(nil)
	if empty == "" {
		t.Fatal("an empty inventory produced no digest")
	}
	if empty == InventoryDigest(comps()) {
		t.Error("an empty inventory digests the same as a populated one")
	}
	if InventoryDigest(nil) != InventoryDigest([]Component{}) {
		t.Error("nil and empty produced different digests")
	}
}
