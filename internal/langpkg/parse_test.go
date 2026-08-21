package langpkg

import (
	"strings"
	"testing"
)

// Verbatim from a real .dist-info/METADATA, including the long description
// that follows the header block and dwarfs it.
const realMetadata = `Metadata-Version: 2.1
Name: argcomplete
Version: 3.6.3
Summary: Bash tab completion for argparse
Home-page: https://github.com/kislyuk/argcomplete
Author: Andrey Kislyuk
Author-email: kislyuk@gmail.com
License: Apache Software License
Classifier: Development Status :: 5 - Production/Stable
Requires-Python: >=3.8
Description-Content-Type: text/markdown

# argcomplete

Name: this line is inside the description and must not be read as a header.
Version: 999.999
`

func TestParsePythonMetadata(t *testing.T) {
	p, err := ParsePythonMetadata(strings.NewReader(realMetadata))
	if err != nil {
		t.Fatalf("ParsePythonMetadata: %v", err)
	}
	if p.Name != "argcomplete" {
		t.Errorf("Name = %q", p.Name)
	}
	// The description repeats Name and Version. Parsing must stop at the blank
	// line, or a package's own prose renames it.
	if p.Version != "3.6.3" {
		t.Errorf("Version = %q, want 3.6.3 -- the header block, not the description", p.Version)
	}
	if p.Author != "Andrey Kislyuk" {
		t.Errorf("Author = %q", p.Author)
	}
	if p.Type != TypePython || p.Language != "python" {
		t.Errorf("Type = %q, Language = %q", p.Type, p.Language)
	}
}

func TestParsePythonMetadataFallsBackToEmail(t *testing.T) {
	p, err := ParsePythonMetadata(strings.NewReader(
		"Name: thing\nVersion: 1.0\nAuthor-email: someone@example.com\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Author != "someone@example.com" {
		t.Errorf("Author = %q, want the email when no plain Author is given", p.Author)
	}
}

func TestParsePythonMetadataRejectsIncomplete(t *testing.T) {
	for _, in := range []string{
		"",
		"Metadata-Version: 2.1\n",
		"Name: thing\n",  // no version
		"Version: 1.0\n", // no name
		"not headers at all\n",
	} {
		if _, err := ParsePythonMetadata(strings.NewReader(in)); !NotAPackage(err) {
			t.Errorf("ParsePythonMetadata(%q) err = %v, want not-a-package", in, err)
		}
	}
}

func TestParsePackageJSON(t *testing.T) {
	cases := []struct {
		name, in, wantName, wantVersion, wantAuthor string
	}{
		{"author as a string",
			`{"name":"lodash","version":"4.17.21","author":"John-David Dalton <john@example.com>"}`,
			"lodash", "4.17.21", "John-David Dalton <john@example.com>"},
		{"author as an object",
			`{"name":"express","version":"4.18.2","author":{"name":"TJ Holowaychuk","email":"tj@example.com"}}`,
			"express", "4.18.2", "TJ Holowaychuk"},
		{"author object with only an email",
			`{"name":"x","version":"1.0.0","author":{"email":"a@b.c"}}`,
			"x", "1.0.0", "a@b.c"},
		{"no author",
			`{"name":"y","version":"2.0.0"}`, "y", "2.0.0", ""},
		{"scoped package",
			`{"name":"@babel/core","version":"7.24.0"}`, "@babel/core", "7.24.0", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParsePackageJSON(strings.NewReader(tc.in))
			if err != nil {
				t.Fatalf("ParsePackageJSON: %v", err)
			}
			if p.Name != tc.wantName || p.Version != tc.wantVersion || p.Author != tc.wantAuthor {
				t.Errorf("got %+v", p)
			}
			if p.Type != TypeNPM || p.Language != "javascript" {
				t.Errorf("Type = %q, Language = %q", p.Type, p.Language)
			}
		})
	}
}

// Most package.json files under a project tree are not installed packages.
// They must be rejected quietly rather than reported as errors.
func TestParsePackageJSONRejectsNonPackages(t *testing.T) {
	for _, in := range []string{
		`{}`,
		`{"name":"project"}`,          // no version
		`{"version":"1.0.0"}`,         // no name
		`{"scripts":{"build":"tsc"}}`, // a config fragment
		`not json at all`,
		``,
	} {
		if _, err := ParsePackageJSON(strings.NewReader(in)); !NotAPackage(err) {
			t.Errorf("ParsePackageJSON(%q) err = %v, want not-a-package", in, err)
		}
	}
}

// Classify decides whether a generic file name is really package metadata.
func TestClassify(t *testing.T) {
	cases := map[string]string{
		`C:\Python311\Lib\site-packages\argcomplete-3.6.3.dist-info\METADATA`: TypePython,
		`C:\app\venv\Lib\site-packages\flask-3.0.0.dist-info\METADATA`:        TypePython,
		`C:\Python311\Lib\site-packages\setuptools.egg-info\PKG-INFO`:         TypePython,
		`C:/mixed/separators/thing.dist-info/METADATA`:                        TypePython,
		`C:\app\node_modules\lodash\package.json`:                             TypeNPM,
		`C:\app\package.json`: TypeNPM,

		// METADATA and PKG-INFO are generic names. Outside a .dist-info or
		// .egg-info directory they are something else entirely.
		`C:\docs\METADATA`:             "",
		`C:\src\myproject\PKG-INFO`:    "",
		`C:\Windows\System32\METADATA`: "",
		`METADATA`:                     "",
		``:                             "",
	}
	for path, want := range cases {
		if got := Classify(path); got != want {
			t.Errorf("Classify(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestIsManifest(t *testing.T) {
	for _, n := range []string{"METADATA", "PKG-INFO", "package.json"} {
		if !IsManifest(n) {
			t.Errorf("IsManifest(%q) = false", n)
		}
	}
	for _, n := range []string{"metadata", "package-lock.json", "setup.py", "RECORD", ""} {
		if IsManifest(n) {
			t.Errorf("IsManifest(%q) = true", n)
		}
	}
}

func TestPURL(t *testing.T) {
	cases := []struct {
		p    Package
		want string
	}{
		{Package{Name: "argcomplete", Version: "3.6.3", Type: TypePython}, "pkg:pypi/argcomplete@3.6.3"},
		// PyPI names are case-insensitive and PURL records them lowercase.
		{Package{Name: "Flask", Version: "3.0.0", Type: TypePython}, "pkg:pypi/flask@3.0.0"},
		{Package{Name: "lodash", Version: "4.17.21", Type: TypeNPM}, "pkg:npm/lodash@4.17.21"},
		// A scoped npm name keeps the "@" percent-encoded, per the PURL
		// specification. pkg:npm/babel/core would name a different, unscoped
		// package.
		{Package{Name: "@babel/core", Version: "7.24.0", Type: TypeNPM}, "pkg:npm/%40babel/core@7.24.0"},
		{Package{Name: "x", Version: "1", Type: "unknown"}, ""},
	}
	for _, tc := range cases {
		if got := PURL(tc.p); got != tc.want {
			t.Errorf("PURL(%+v) = %q, want %q", tc.p, got, tc.want)
		}
	}
}
