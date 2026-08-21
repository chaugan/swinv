// Package langpkg reads language-ecosystem packages from their installed
// metadata files.
//
// It exists for Windows. The Linux collector gets roughly forty ecosystems from
// Syft, and the Windows collector cannot: Syft's directory resolver opens every
// file in the tree it indexes, which on Windows means every open is inspected by
// antivirus, and scanning C:\Program Files that way did not finish inside ten
// minutes.
//
// So the discovery and the reading are separated. MFT enumeration already
// produces every filename on the volume without opening anything, and installed
// packages announce themselves by file name -- METADATA inside a .dist-info
// directory, PKG-INFO inside .egg-info, package.json. That means the same pass
// that finds executables finds manifests, and only the manifests are opened.
//
// The cost of this is reimplementing two of Syft's catalogers. The alternative
// was paying its indexer over three million files to reuse forty of them.
package langpkg

import "strings"

// Package is one installed language-ecosystem package.
type Package struct {
	Name    string
	Version string

	// Type is the swinv component type: "python" or "npm".
	Type string

	// Language is the ecosystem's language, matching what Syft records on
	// Linux so the two platforms produce comparable rows.
	Language string

	// Author is whatever the manifest calls the author or maintainer. Free
	// text, frequently absent, and often carrying an email address.
	Author string

	// Path is the manifest the package was read from.
	Path string
}

const (
	TypePython = "python"
	TypeNPM    = "npm"
)

// Manifest names worth opening. Discovery matches on these, so the list is the
// contract between MFT enumeration and this package.
const (
	pythonMetadata = "METADATA" // inside <name>-<version>.dist-info
	pythonPKGInfo  = "PKG-INFO" // inside <name>.egg-info
	npmManifest    = "package.json"
)

// IsManifest reports whether a file name might be installed-package metadata.
//
// Name only, because that is all MFT enumeration provides and all that can be
// known without opening the file. The parent directory decides whether a
// METADATA is really Python metadata, which Classify checks.
func IsManifest(name string) bool {
	switch name {
	case pythonMetadata, pythonPKGInfo, npmManifest:
		return true
	}
	return false
}

// Classify reports which ecosystem a manifest path belongs to, or "" if it is
// not installed-package metadata after all.
//
// METADATA and PKG-INFO are generic names. Python's are distinguished by
// living inside a .dist-info or .egg-info directory, which is what separates an
// installed distribution from a source tree or an unrelated file that happens
// to share the name.
func Classify(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")

	i := strings.LastIndex(path, "/")
	if i < 0 {
		return ""
	}
	name, dir := path[i+1:], path[:i]

	switch name {
	case npmManifest:
		return TypeNPM
	case pythonMetadata, pythonPKGInfo:
		lower := strings.ToLower(dir)
		if strings.HasSuffix(lower, ".dist-info") || strings.HasSuffix(lower, ".egg-info") {
			return TypePython
		}
	}
	return ""
}

// PURL renders a package's identity as a Package URL.
//
// Unlike the Windows registry entries, these ecosystems have canonical PURL
// types, so there is a real identifier to emit rather than a guess -- which is
// why these components carry one and the registry-derived ones do not.
func PURL(p Package) string {
	switch p.Type {
	case TypePython:
		return "pkg:pypi/" + strings.ToLower(p.Name) + "@" + p.Version
	case TypeNPM:
		// A scoped name is "@scope/name"; PURL keeps the scope as the
		// namespace, and the leading "@" is not part of it.
		name := strings.TrimPrefix(p.Name, "@")
		return "pkg:npm/" + name + "@" + p.Version
	}
	return ""
}
