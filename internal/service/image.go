package service

import "strings"

// imagePURL renders the pkg:oci form of an image reference.
//
// A locator, not an identity. No vulnerability matcher resolves an OCI PURL --
// Grype has no oci matcher, OSV and OSS Index carry no OCI coordinates, and
// Dependency-Track ingests one, finds nothing, and shows the component clean.
// So it never appears in a Components list. It is emitted so a consumer can
// join to an image scan performed elsewhere, which is what actually produces
// findings for an image.
func imagePURL(ref, digest string) string {
	if ref == "" {
		return ""
	}
	repo, tag := splitImageRef(ref)
	name := repo
	if i := strings.LastIndex(repo, "/"); i >= 0 {
		name = repo[i+1:]
	}
	if name == "" {
		return ""
	}
	out := "pkg:oci/" + strings.ToLower(name)
	if digest != "" {
		// The spec percent-encodes the colon in the version.
		out += "@" + strings.Replace(digest, ":", "%3A", 1)
	}
	var qualifiers []string
	if repo != "" {
		qualifiers = append(qualifiers, "repository_url="+repo)
	}
	if tag != "" {
		qualifiers = append(qualifiers, "tag="+tag)
	}
	if len(qualifiers) > 0 {
		out += "?" + strings.Join(qualifiers, "&")
	}
	return out
}

// splitImageRef separates a reference into repository and tag, leaving a
// registry host with a port intact.
func splitImageRef(ref string) (repo, tag string) {
	repo = ref
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		repo, tag = ref[:i], ref[i+1:]
	}
	if i := strings.Index(repo, "@"); i >= 0 {
		repo = repo[:i]
	}
	return strings.ToLower(repo), tag
}
