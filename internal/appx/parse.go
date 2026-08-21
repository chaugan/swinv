// Package appx reads Store and MSIX packages, and the Windows updates the
// component store records.
//
// Both come from the registry and open no files, which is the same shape as
// the uninstall-key reader: on Windows, metadata answers the question and the
// filesystem does not.
package appx

import "strings"

// Package is one Appx/MSIX package.
type Package struct {
	// FullName is the package identity Windows uses everywhere, e.g.
	// "Microsoft.WindowsTerminal_3001.23.20211.0_neutral_~_8wekyb3d8bbwe".
	FullName string

	Name         string
	Version      string
	Architecture string

	// PublisherID is the hash Windows derives from the publisher certificate.
	// It is not a name, but it is stable and distinguishes two packages that
	// share one.
	PublisherID string

	// RootFolder is where the package is installed. It is what separates a
	// Store app under WindowsApps from an operating-system app under
	// Windows\SystemApps.
	RootFolder string
}

// parseFullName splits a package full name into its parts.
//
// The format is Name_Version_Architecture_ResourceId_PublisherId, always five
// underscore-separated fields. Two of them are routinely odd: the resource id
// is often empty, giving a double underscore, or the literal "~", and the name
// itself is sometimes a GUID for system apps. Neither is an error.
//
// Returns false rather than guessing when the shape does not match. A package
// reported with the wrong version is worse than one not reported at all.
func parseFullName(fullName string) (Package, bool) {
	parts := strings.Split(fullName, "_")
	if len(parts) != 5 {
		return Package{}, false
	}

	p := Package{
		FullName:     fullName,
		Name:         parts[0],
		Version:      parts[1],
		Architecture: parts[2],
		PublisherID:  parts[4],
	}
	if p.Name == "" || p.Version == "" {
		return Package{}, false
	}
	return p, true
}

// isResourcePackage reports whether a package is a per-language or per-scale
// resource bundle rather than an application.
//
// Windows installs one of these per display scale and per language --
// "...neutral_split.scale-125_..." -- and counting them as installed software
// turns one application into a dozen entries that differ only in an asset
// resolution.
func isResourcePackage(architecture string) bool {
	return strings.HasPrefix(strings.ToLower(architecture), "split.")
}

// isOperatingSystemApp reports whether a package is part of Windows rather
// than something installed on it.
//
// Windows\SystemApps holds the shell: the file picker, Explorer, the start
// menu. They are Appx packages by construction and are not installed software
// in any sense an operator cares about, so they are excluded for the same
// reason WinSxS is.
func isOperatingSystemApp(rootFolder string) bool {
	lower := strings.ToLower(strings.ReplaceAll(rootFolder, "/", `\`))
	return strings.Contains(lower, `\windows\systemapps\`) ||
		strings.Contains(lower, `\windows\immersivecontrolpanel`)
}

// kbFromCBSPackage extracts the knowledge-base number from a Component Based
// Servicing package name.
//
// The component store records one key per component per update, so a single
// update appears thousands of times:
//
//	Package_10_for_KB5120708~31bf3856ad364e35~amd64~~10.0.9344.1
//	Package_11_for_KB5120708~31bf3856ad364e35~amd64~~10.0.9344.1
//
// A real machine had 7,844 such keys. The KB number is the part an operator
// patches by, so the caller deduplicates on what this returns.
//
// Returns "" when the name carries no KB number, which is most of them: the
// store also holds feature packages, language packs and the base OS
// components, none of which are updates.
func kbFromCBSPackage(name string) string {
	upper := strings.ToUpper(name)

	i := strings.Index(upper, "KB")
	if i < 0 {
		return ""
	}
	// A KB reference must start at a word boundary, or "...~amd64~~kb..." in
	// the middle of a component name would match something that is not one.
	if i > 0 {
		prev := upper[i-1]
		if prev != '_' && prev != '~' && prev != '.' && prev != '-' {
			return ""
		}
	}

	digits := upper[i+2:]
	end := 0
	for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
		end++
	}
	// Real KB numbers are six or seven digits. Requiring several rules out
	// version fragments that happen to follow the letters.
	if end < 6 {
		return ""
	}
	return "KB" + digits[:end]
}
