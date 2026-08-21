package scan

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/chaugan/swinv/internal/hostfacts"
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
	releases := readRootReleases(nested)

	for i := range components {
		root := rootOf(components[i].Locations, nested)
		components[i].Root = root
		if root == hostRoot {
			continue
		}

		components[i].PURL = stripDistroClaim(components[i].PURL)

		// The nested root's own release, where it states one. This is the
		// answer to a question consumers were inferring from the directory
		// name -- core18 meaning Ubuntu 18.04 -- which is a Canonical naming
		// convention rather than a fact, and is guesswork the scanner does not
		// have to leave to them.
		if r, ok := releases[root]; ok {
			components[i].Attributes = withRootRelease(components[i].Attributes, r)
		}
	}
	return components
}

// rootRelease is what a nested root says about itself.
type rootRelease struct{ id, versionID string }

// readRootReleases reads each nested root's own os-release.
//
// Two small files per root, and a root without one simply reports nothing:
// an app snap or an unpacked layer need not be a distribution at all.
func readRootReleases(nested []string) map[string]rootRelease {
	out := make(map[string]rootRelease, len(nested))

	for _, root := range nested {
		for _, name := range []string{"etc/os-release", "usr/lib/os-release"} {
			f, err := os.Open(filepath.Join(root, name))
			if err != nil {
				continue
			}
			values := hostfacts.ParseOSRelease(f)
			f.Close()

			if id := values["ID"]; id != "" {
				out[root] = rootRelease{id: id, versionID: values["VERSION_ID"]}
				break
			}
		}
	}
	return out
}

func withRootRelease(attrs map[string]string, r rootRelease) map[string]string {
	if attrs == nil {
		attrs = make(map[string]string, 2)
	}
	if r.id != "" {
		attrs["root_os_id"] = r.id
	}
	if r.versionID != "" {
		attrs["root_os_version_id"] = r.versionID
	}
	return attrs
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
