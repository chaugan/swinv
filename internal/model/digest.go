package model

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// InventoryDigest is a stable fingerprint of what is installed.
//
// Its whole purpose is to be compared against the previous scan's value on the
// same host, so it must change when the inventory does and must not change for
// any other reason. Two runs against an unchanged machine have to produce the
// same digest, or a fleet reports every host as changed on every scan and the
// optimisation it exists for is worse than useless.
//
// It is deliberately built from identity alone -- type, name, version, root and
// PURL, the same tuple Normalize deduplicates on -- and not from the whole
// component. Locations move when a file is relinked, found_by changes when a
// cataloger is renamed upstream, sha256 appears and disappears with --hash, and
// none of those mean a package was installed or removed. A digest that moved
// with them would report change constantly and be ignored within a week.
//
// The value is opaque: nothing outside this function should parse it, and it
// carries no guarantee of stability across swinv versions. A host whose digest
// algorithm changes looks changed exactly once, which is harmless -- the full
// component list is sent, and the next scan agrees with it.
func InventoryDigest(components []Component) string {
	lines := make([]string, 0, len(components))
	for _, c := range components {
		// Tab-separated because a tab cannot occur in any of these fields,
		// while "|" and ":" occur in PURLs and Windows paths routinely.
		// SHA256 is included when the scan recorded it (--hash). Identity
		// alone cannot see a binary replaced in place under the same
		// version string - the import probe re-reads the new file every
		// run, but an identity-only digest would suppress the corrected
		// records as "unchanged". The cost is one full resend when the
		// --hash flag itself is toggled, which a timer does never and an
		// operator does deliberately.
		lines = append(lines, strings.Join([]string{
			c.Type, c.Name, c.Version, c.Root, c.PURL, c.SHA256,
		}, "\t"))
	}
	// Sorted, so the digest does not depend on the order the catalogers
	// happened to run in. Normalize already sorts, but this must hold for any
	// caller.
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		_, _ = h.Write([]byte(l))
		_, _ = h.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
