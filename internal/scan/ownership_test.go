package scan

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"

	"github.com/chaugan/swinv/internal/model"
)

// stubID stands in for a Syft package in a relationship, which only needs to
// be identifiable.
type stubID string

func (s stubID) ID() artifact.ID { return artifact.ID(s) }

func own(from, to stubID) artifact.Relationship {
	return artifact.Relationship{From: from, To: to, Type: artifact.OwnershipByFileOverlapRelationship}
}

// TestApplyFileOwnershipLinksTheReportedCase is the case from the report: a
// distribution-installed Python package and the deb that owns its files. Both
// rows are correct and both are kept; what was missing was the link, and
// without it a consumer compares Ubuntu's backported version against upstream
// numbering and reports a patched host as thirty-seven releases behind.
func TestApplyFileOwnershipLinksTheReportedCase(t *testing.T) {
	components := []model.Component{
		{Name: "python3-cryptography", Version: "2.1.4-1ubuntu1.4+esm1", Type: "deb",
			PURL: "pkg:deb/ubuntu/python3-cryptography@2.1.4-1ubuntu1.4%2Besm1", Root: "/"},
		{Name: "cryptography", Version: "2.1.4", Type: "python",
			PURL: "pkg:pypi/cryptography@2.1.4", Root: "/"},
	}
	byID := map[artifact.ID]int{"deb": 0, "py": 1}

	out := applyFileOwnership(components, byID, []artifact.Relationship{own("deb", "py")})

	if got := out[1].OwnedBy; got != "pkg:deb/ubuntu/python3-cryptography@2.1.4-1ubuntu1.4%2Besm1" {
		t.Errorf("the python component was not linked to its deb: %q", got)
	}
	if out[0].OwnedBy != "" {
		t.Errorf("the deb was given an owner: %q", out[0].OwnedBy)
	}
}

// One OS package owning another's files is ordinary -- binutils-common ships
// headers binutils-x86-64-linux-gnu references -- and says nothing about
// backporting, since one vendor patches both on one schedule. Recording it
// would add noise to a field whose whole value is that its presence means
// something.
func TestApplyFileOwnershipIgnoresOSToOS(t *testing.T) {
	components := []model.Component{
		{Name: "binutils-common", Type: "deb", PURL: "pkg:deb/ubuntu/binutils-common@2.46", Root: "/"},
		{Name: "binutils-x86-64-linux-gnu", Type: "deb", PURL: "pkg:deb/ubuntu/binutils-x86-64@2.46", Root: "/"},
	}
	out := applyFileOwnership(components, map[artifact.ID]int{"a": 0, "b": 1},
		[]artifact.Relationship{own("a", "b")})

	if out[1].OwnedBy != "" {
		t.Errorf("one deb was recorded as owning another: %q", out[1].OwnedBy)
	}
}

// TestApplyFileOwnershipDoesNotCrossRoots pins a wrong link seen on a real
// host: the host's bash 5.3 claimed to own bash 5.2.15 inside a nested rootfs,
// because the two share a path suffix. A confident wrong answer in a field a
// consumer trusts precisely because the scanner produced it.
func TestApplyFileOwnershipDoesNotCrossRoots(t *testing.T) {
	components := []model.Component{
		{Name: "python3-foo", Type: "deb", PURL: "pkg:deb/ubuntu/python3-foo@2.0", Root: "/"},
		{Name: "foo", Type: "python", PURL: "pkg:pypi/foo@1.0", Root: "/snap/core18/2999"},
	}
	out := applyFileOwnership(components, map[artifact.ID]int{"deb": 0, "py": 1},
		[]artifact.Relationship{own("deb", "py")})

	if out[1].OwnedBy != "" {
		t.Errorf("ownership crossed a filesystem root: %q", out[1].OwnedBy)
	}
}

// A package installed by pip rather than by the distribution has no owner, and
// must not acquire one: those genuinely should be assessed against upstream.
func TestApplyFileOwnershipLeavesUnownedAlone(t *testing.T) {
	components := []model.Component{
		{Name: "requests", Version: "2.31.0", Type: "python", PURL: "pkg:pypi/requests@2.31.0", Root: "/"},
	}
	out := applyFileOwnership(components, map[artifact.ID]int{"py": 0}, nil)
	if out[0].OwnedBy != "" {
		t.Errorf("an unowned package acquired an owner: %q", out[0].OwnedBy)
	}
}

// Relationships of other types, and references to packages that were filtered
// out, must not produce links or panics.
func TestApplyFileOwnershipIgnoresIrrelevantRelationships(t *testing.T) {
	components := []model.Component{
		{Name: "python3-foo", Type: "deb", PURL: "pkg:deb/ubuntu/python3-foo@2.0", Root: "/"},
		{Name: "foo", Type: "python", PURL: "pkg:pypi/foo@1.0", Root: "/"},
	}
	byID := map[artifact.ID]int{"deb": 0, "py": 1}

	out := applyFileOwnership(components, byID, []artifact.Relationship{
		{From: stubID("deb"), To: stubID("py"), Type: artifact.ContainsRelationship},
		{From: stubID("gone"), To: stubID("py"), Type: artifact.OwnershipByFileOverlapRelationship},
		{From: stubID("deb"), To: stubID("gone"), Type: artifact.OwnershipByFileOverlapRelationship},
		{From: stubID("deb"), To: stubID("deb"), Type: artifact.OwnershipByFileOverlapRelationship},
	})

	if out[1].OwnedBy != "" {
		t.Errorf("a non-ownership relationship produced a link: %q", out[1].OwnedBy)
	}
}

func TestIsOSPackage(t *testing.T) {
	for _, typ := range []string{"deb", "rpm", "apk", "alpm", "portage"} {
		if !isOSPackage(typ) {
			t.Errorf("isOSPackage(%q) = false, want true", typ)
		}
	}
	for _, typ := range []string{"python", "npm", "go-module", "rust-crate", "binary", "msix", ""} {
		if isOSPackage(typ) {
			t.Errorf("isOSPackage(%q) = true, want false", typ)
		}
	}
}
