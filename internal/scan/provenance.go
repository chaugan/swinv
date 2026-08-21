package scan

import (
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// hostRoot is the value Component.Root carries for software installed on the
// scanned machine itself, as opposed to inside something on it.
const hostRoot = "/"

// assignRoots records which filesystem root each component was found in, and
// removes the distribution claim from packages that came from a different one.
//
// Syft stamps every package with the *scanned host's* distribution, because
// that is what it detected at the scan root. For a package inside a snap base
// or a container layer that is wrong, and wrong in a way that survives into
// vulnerability matching: a Debian 12 openssl in a snap arrives as
// pkg:deb/ubuntu/openssl@3.0.11-1~deb12u2?distro=ubuntu-26.04, and a consumer
// that trusts distro= compares a Debian version against Ubuntu's fixed
// versions. Both the "is it affected" and "is it fixed" answers are then
// meaningless.
//
// Reported by a downstream matcher. On the reporter's host 867 of 14,347
// components -- roughly 6% -- lived in a root other than the host's, and the
// snap bases are whole operating systems with their own release and patch
// cadence: core18 is Ubuntu 18.04, core20 is 20.04.
//
// Removing the claim rather than correcting it is deliberate. The nested root's
// own os-release could be read, but a missing qualifier is honest where a wrong
// one is not, and a consumer can tell the difference.
func assignRoots(components []model.Component, nested []string) []model.Component {
	for i := range components {
		root := rootOf(components[i].Locations, nested)
		components[i].Root = root
		if root != hostRoot {
			components[i].PURL = stripDistroClaim(components[i].PURL)
		}
	}
	return components
}

// rootOf finds the nested root a component's locations lie under.
//
// A component whose locations span more than one root is reported under the
// first, which is a compromise: once Root joins the deduplication key such
// components stop being merged in the first place, so this only decides the
// rare case of one cataloger genuinely reading evidence from two roots.
func rootOf(locations []string, nested []string) string {
	for _, loc := range locations {
		for _, root := range nested {
			if loc == root || strings.HasPrefix(loc, strings.TrimSuffix(root, "/")+"/") {
				return root
			}
		}
	}
	return hostRoot
}

// stripDistroClaim removes a PURL's assertions about which distribution a
// package came from: the distro= qualifier and the namespace.
//
// Both say the same wrong thing. pkg:deb/ubuntu/openssl names Ubuntu in the
// namespace as surely as distro=ubuntu-26.04 does in the qualifier, and a
// consumer matching on either makes the same mistake. What survives --
// pkg:deb/openssl@3.0.11-1~deb12u2?arch=amd64 -- is exactly what is known: a
// Debian-format package of that name and version, of unstated origin.
func stripDistroClaim(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return purl
	}

	body, qualifiers, hasQualifiers := strings.Cut(purl, "?")
	body, subpath, hasSubpath := strings.Cut(body, "#")

	// pkg:type/namespace/name@version -- drop the namespace, if there is one.
	if segments := strings.Split(strings.TrimPrefix(body, "pkg:"), "/"); len(segments) > 2 {
		body = "pkg:" + segments[0] + "/" + strings.Join(segments[len(segments)-1:], "/")
	}

	if hasQualifiers {
		var kept []string
		for _, q := range strings.Split(qualifiers, "&") {
			if key, _, _ := strings.Cut(q, "="); !strings.EqualFold(key, "distro") {
				kept = append(kept, q)
			}
		}
		if len(kept) > 0 {
			body += "?" + strings.Join(kept, "&")
		}
	}
	if hasSubpath {
		body += "#" + subpath
	}
	return body
}
