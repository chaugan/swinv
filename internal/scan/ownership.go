package scan

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"

	"github.com/chaugan/swinv/internal/model"
)

// applyFileOwnership links a language package to the OS package that installed
// it, where one did.
//
// Syft already computes this and swinv was discarding it. When a distribution
// ships a Python or Node package, the OS package's file list contains the very
// evidence file the language cataloger read -- Ubuntu's python3-cryptography
// owns the egg-info directory that produces the PyPI record -- and Syft records
// that as an ownership-by-file-overlap relationship.
//
// Both rows are kept. The OS package is what the vendor patches; the ecosystem
// package is what upstream advisories are written against, and dropping either
// loses something. What was missing was the link, and without it a consumer
// assessing the ecosystem row against upstream compares a backported version
// against upstream's own numbering. Reported as 442 false findings on one host,
// where Ubuntu's cryptography 2.1.4+esm1 is patched and PyPI's 2.1.4 reads as
// thirty-seven releases behind.
//
// Consumers can approximate this from install paths -- dist-packages against
// site-packages -- but that is a convention being pattern-matched in the place
// with the least information, when the scanner has the answer.
func applyFileOwnership(components []model.Component, byID map[artifact.ID]int, relationships []artifact.Relationship) []model.Component {
	for _, r := range relationships {
		if r.Type != artifact.OwnershipByFileOverlapRelationship {
			continue
		}

		// From owns the file, To references it.
		owner, ok := byID[r.From.ID()]
		if !ok {
			continue
		}
		owned, ok := byID[r.To.ID()]
		if !ok || owner == owned {
			continue
		}

		// Only an OS package can vouch for a backported version. A language
		// package that happens to own another's file says nothing about who
		// patches it, and recording that would invite the same wrong
		// conclusion in the other direction.
		if !isOSPackage(components[owner].Type) {
			continue
		}

		// And only an ecosystem package can be vouched for. One OS package
		// owning another's file is ordinary -- binutils-common ships headers
		// binutils-x86-64-linux-gnu references -- and says nothing about
		// backporting, because both are patched by the same vendor on the
		// same schedule. Recording it adds noise to the field whose entire
		// value is that its presence means something.
		if isOSPackage(components[owned].Type) {
			continue
		}

		// Ownership cannot cross a filesystem root. Without this the host's
		// bash claims to own a different version of bash inside a nested
		// rootfs, purely because the two share a path suffix -- which is the
		// wrong answer stated confidently, in a field a consumer would trust
		// precisely because it came from the scanner.
		if components[owner].Root != components[owned].Root {
			continue
		}

		if purl := components[owner].PURL; purl != "" {
			components[owned].OwnedBy = purl
		}
	}
	return components
}

// isOSPackage reports whether a component type is a distribution package --
// the kind whose vendor backports fixes without changing the upstream version.
func isOSPackage(typ string) bool {
	switch pkg.Type(typ) {
	case pkg.DebPkg, pkg.RpmPkg, pkg.ApkPkg, pkg.AlpmPkg, pkg.PortagePkg:
		return true
	}
	return false
}
