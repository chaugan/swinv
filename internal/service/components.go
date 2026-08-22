package service

import (
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// ContainerComponents lifts the packages found inside containers into the
// inventory's own component list.
//
// Without this the PURLs in containers[] exist nowhere else in the document,
// which breaks two things at once: a CycloneDX dependency edge pointing at a
// bom-ref no component has, and every consumer whose CVE matching reads
// components[] and nothing else -- which is most of them, including
// `grype sbom:`.
//
// The coverage is deliberately partial and says so. Only the packages owning a
// listening executable were probed, because cataloguing whole container
// filesystems costs a full walk each and this is not a container scanner. A
// consumer must not read these rows as the container's inventory, so every one
// carries scan_scope=listening-executables-only, and the root names the
// container they came from rather than "/".
func ContainerComponents(containers []model.Container) []model.Component {
	var out []model.Component
	for _, c := range containers {
		for _, s := range c.Services {
			for _, purl := range s.Components {
				if comp, ok := componentFor(c, purl); ok {
					out = append(out, comp)
				}
			}
		}
	}
	return out
}

func componentFor(c model.Container, purl string) (model.Component, bool) {
	name, version, typ, ok := parsePURL(purl)
	if !ok {
		return model.Component{}, false
	}

	attributes := map[string]string{
		"scan_scope":   "listening-executables-only",
		"container_id": c.ID,
	}
	if c.Name != "" {
		attributes["container_name"] = c.Name
	}
	// The same key the runtime route sets. Without it a consumer filtering on
	// container_state silently drops whatever the targeted probe found, which
	// is the *more* precisely identified half of the two.
	if c.State != "" {
		attributes["container_state"] = c.State
	}
	if c.Image != nil {
		if c.Image.Ref != "" {
			attributes["container_image"] = c.Image.Ref
		}
		if c.Image.ManifestDigest != "" {
			attributes["container_image_digest"] = c.Image.ManifestDigest
		}
	}

	return model.Component{
		Name:    name,
		Version: version,
		Type:    typ,
		PURL:    purl,
		// A container is a different operating system from its host, with its
		// own release and its own patch state, which is exactly what Root
		// exists to keep separate.
		Root:       "container:" + shortID(c.ID),
		FoundBy:    "container-package-probe",
		Attributes: attributes,
	}, true
}

// parsePURL pulls the name, version and type back out of a PURL this package
// built. It is not a general parser: it handles the forms ctrpkg emits.
func parsePURL(purl string) (name, version, typ string, ok bool) {
	rest, found := strings.CutPrefix(purl, "pkg:")
	if !found {
		return "", "", "", false
	}
	typ, rest, found = strings.Cut(rest, "/")
	if !found || typ == "" {
		return "", "", "", false
	}
	// Drop the qualifiers.
	rest, _, _ = strings.Cut(rest, "?")
	// An optional namespace precedes the name.
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		rest = rest[i+1:]
	}
	name, version, found = strings.Cut(rest, "@")
	if !found || name == "" || version == "" {
		return "", "", "", false
	}
	return name, version, typ, true
}
