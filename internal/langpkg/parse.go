package langpkg

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxManifestSize caps how much of a manifest is read.
//
// These files are metadata and are measured in kilobytes; a package.json in the
// wild is occasionally megabytes of bundled data. The cap bounds what one
// malformed or hostile file can cost a scan that is opening thousands of them.
const maxManifestSize = 1 << 20

// ParsePythonMetadata reads a .dist-info/METADATA or .egg-info/PKG-INFO file.
//
// The format is RFC 822-style headers, as Python packaging specifies. Only the
// header block is read: METADATA continues into the package's long description,
// which is the bulk of the file and is of no interest, so parsing stops at the
// first blank line.
func ParsePythonMetadata(r io.Reader) (Package, error) {
	p := Package{Type: TypePython, Language: "python"}

	scanner := bufio.NewScanner(io.LimitReader(r, maxManifestSize))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			break // end of the header block
		}
		// Continuation lines are indented; none of the fields read here use
		// them, so they are skipped rather than folded.
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)

		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			p.Name = value
		case "version":
			p.Version = value
		case "author":
			if p.Author == "" {
				p.Author = value
			}
		case "author-email":
			// Only when there is no plain Author: an email alone is a poor
			// vendor string, but it beats nothing.
			if p.Author == "" {
				p.Author = value
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return Package{}, fmt.Errorf("langpkg: reading python metadata: %w", err)
	}

	if p.Name == "" || p.Version == "" {
		return Package{}, errNotAPackage
	}
	return p, nil
}

// npmManifestFields is the subset of package.json worth reading. Author is
// either a string or an object, so it is decoded late.
type npmManifestFields struct {
	Name    string          `json:"name"`
	Version string          `json:"version"`
	Private bool            `json:"private"`
	Author  json.RawMessage `json:"author"`
}

// ParsePackageJSON reads an npm package.json.
//
// Every directory under node_modules carries one, and each is genuinely an
// installed package, so this is the manifest that produces the most rows by
// far. A package.json without both a name and a version is a project file or a
// configuration fragment rather than an installed package.
func ParsePackageJSON(r io.Reader) (Package, error) {
	var m npmManifestFields
	if err := json.NewDecoder(io.LimitReader(r, maxManifestSize)).Decode(&m); err != nil {
		return Package{}, errNotAPackage
	}
	if m.Name == "" || m.Version == "" {
		return Package{}, errNotAPackage
	}

	return Package{
		Name:     m.Name,
		Version:  m.Version,
		Type:     TypeNPM,
		Language: "javascript",
		Author:   npmAuthor(m.Author),
	}, nil
}

// npmAuthor decodes the two shapes package.json allows: a string such as
// "Jane <jane@example.com> (https://example.com)", or an object with a name.
func npmAuthor(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}

	var obj struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		if obj.Name != "" {
			return strings.TrimSpace(obj.Name)
		}
		return strings.TrimSpace(obj.Email)
	}
	return ""
}

// errNotAPackage marks a manifest that parsed but does not describe an
// installed package. Not an error worth surfacing: on a real volume most
// package.json files under a project tree are exactly this.
var errNotAPackage = errors.New("langpkg: not an installed package")

// NotAPackage reports whether an error means the file simply was not one.
func NotAPackage(err error) bool { return errors.Is(err, errNotAPackage) }
