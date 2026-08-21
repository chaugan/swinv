package hostfacts

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// windows11MinimumBuild is where Windows 11 begins.
//
// This constant exists because the registry lies. HKLM\SOFTWARE\Microsoft\
// Windows NT\CurrentVersion\ProductName still reads "Windows 10 Pro" on a
// Windows 11 machine -- Microsoft never updated it, and a great deal of
// software reports Windows 11 hosts as Windows 10 for exactly this reason.
// The build number is the reliable discriminator.
const windows11MinimumBuild = 22000

// windowsMajorVersion turns a build number into the marketing version, which
// is what an operator groups a fleet by.
//
// Returns an empty string when the build is unparseable, rather than guessing:
// a wrong OS version silently mis-buckets a host, and no answer is easier to
// notice than a confident wrong one.
func windowsMajorVersion(currentBuild string) string {
	build, err := strconv.Atoi(strings.TrimSpace(currentBuild))
	if err != nil || build <= 0 {
		return ""
	}
	if build >= windows11MinimumBuild {
		return "11"
	}
	return "10"
}

// serverRelease matches the year in a Windows Server product name, with an
// optional R2. Anchored to a word boundary so it cannot pick a year out of a
// build number.
var serverRelease = regexp.MustCompile(`\b(20[0-2][0-9])(\s+R2)?\b`)

// windowsVersionID is the value an operator groups a fleet by.
//
// Client and Server share build numbers -- Windows 11 24H2 and Windows Server
// 2025 are both build 26100 -- so the build alone answers the wrong question
// for a server. A CI runner reporting os_version_id "11" while calling itself
// "Windows Server 2025 Datacenter" is how this was noticed.
//
// InstallationType is the discriminator the registry provides: "Client",
// "Server", or "Server Core". For a server the release year is the version
// anyone means; for a client it is the marketing major.
func windowsVersionID(productName, currentBuild, installationType string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(installationType)), "server") {
		if m := serverRelease.FindString(productName); m != "" {
			return strings.Join(strings.Fields(m), " ")
		}
	}
	return windowsMajorVersion(currentBuild)
}

// windowsKernelRelease assembles the full build identity, the closest Windows
// analogue to a Linux kernel release: 10.0.26100.1234.
//
// CurrentMajorVersionNumber and CurrentMinorVersionNumber have been 10 and 0
// since Windows 10 and remain so on Windows 11, so they are read rather than
// assumed, but they are not what distinguishes the two.
func windowsKernelRelease(major, minor, build, ubr string) string {
	parts := []string{
		firstNonEmpty(strings.TrimSpace(major), "10"),
		firstNonEmpty(strings.TrimSpace(minor), "0"),
	}
	if b := strings.TrimSpace(build); b != "" {
		parts = append(parts, b)
	}
	if u := strings.TrimSpace(ubr); u != "" && u != "0" {
		parts = append(parts, u)
	}
	return strings.Join(parts, ".")
}

// windowsPrettyName builds the human-readable OS name.
//
// It corrects the registry's ProductName rather than repeating it, because
// "Windows 10 Pro" on a Windows 11 host is the single most misleading string
// Windows offers about itself. The edition and release ("Pro", "24H2") are
// kept, since those are what distinguish two hosts that share a version.
func windowsPrettyName(productName, displayVersion, currentBuild string) string {
	major := windowsMajorVersion(currentBuild)
	name := strings.TrimSpace(productName)

	// Only client editions carry the wrong name. A server product name says
	// "Windows Server 2025" and is already correct.
	if major == "11" && strings.Contains(name, "Windows 10") && !strings.Contains(name, "Server") {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	if name == "" {
		if major == "" {
			return ""
		}
		name = "Windows " + major
	}

	if v := strings.TrimSpace(displayVersion); v != "" {
		name += " " + v
	}
	if b := strings.TrimSpace(currentBuild); b != "" {
		name += fmt.Sprintf(" (build %s)", b)
	}
	return name
}

// normalizeMachineGUID makes Windows' MachineGuid comparable with a Linux
// machine-id: 32 lowercase hex characters, no separators.
//
// Both identify an installation rather than hardware, and both survive a
// rename, so a fleet dataset can use one column for either. The dashes are the
// only difference worth removing.
func normalizeMachineGUID(guid string) string {
	guid = strings.ToLower(strings.TrimSpace(guid))
	guid = strings.Trim(guid, "{}")
	guid = strings.ReplaceAll(guid, "-", "")

	if len(guid) != 32 {
		return ""
	}
	for _, r := range guid {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return ""
		}
	}
	return guid
}
