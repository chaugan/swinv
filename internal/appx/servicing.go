package appx

import "strings"

// Kind classifies a servicing package.
//
// A flat list of KB numbers is the obvious model and it is wrong. Modern
// Windows quality updates are cumulative: each one replaces its predecessor,
// and the component store records the current one under an identity that
// contains no KB at all. Asking "is KB5121003 installed?" a month later
// false-negatives a fully patched machine. What the classes below record is
// what each stream is *at*, which is the question that keeps meaning something.
type Kind string

const (
	// KindCumulative is the monthly quality update. Its package version is the
	// host's build and UBR, so it says the same thing as kernel_release --
	// which is the point: that is the field to compare, not a KB.
	KindCumulative Kind = "cumulative"

	// KindServicingStack is the servicing stack update, versioned rather than
	// numbered, and usually delivered combined with the cumulative update.
	KindServicingStack Kind = "servicing-stack"

	// KindDotNetRollup is the .NET Framework rollup. It is a separate stream:
	// the OS build does not move when it installs, so the OS UBR says nothing
	// about whether a .NET Framework vulnerability is patched.
	KindDotNetRollup Kind = "dotnet-rollup"

	// KindStandalone is an update identified by its KB number -- out-of-band
	// fixes not yet folded into a cumulative update, and enablement packages.
	// Here a KB genuinely is the identity.
	KindStandalone Kind = "standalone"
)

// Component store package states, from the servicing stack. A package is
// installed for inventory purposes only in the last four.
const (
	stateStaged             = 0x40 // 64
	stateSuperseded         = 0x50 // 80
	stateInstallPending     = 0x60 // 96
	statePartiallyInstalled = 0x65 // 101
	stateInstalled          = 0x70 // 112
	statePermanent          = 0x80 // 128
)

// isInstalledState reports whether a component-store package counts as
// installed.
//
// Reading this is not optional. Superseded packages stay in the store after
// they are replaced: on a real laptop the reader reported two .NET rollups
// from May and July that had both been superseded by August's, because it
// looked only at key names. Those are the store's memory, not the host's patch
// state.
func isInstalledState(state uint64) bool {
	switch state {
	case stateInstallPending, statePartiallyInstalled, stateInstalled, statePermanent:
		return true
	}
	return false
}

// isPendingState reports whether a package is installed but not yet live.
//
// Worth surfacing separately: between a cumulative update installing and the
// machine rebooting, the store says one thing and the running kernel another,
// and an unattended scan in that window reports a patch level the host does
// not yet have.
func isPendingState(state uint64) bool {
	return state == stateInstallPending || state == statePartiallyInstalled
}

// servicing describes one component-store package.
type servicing struct {
	Kind     Kind
	KB       string
	Version  string
	Identity string
}

// parseServicingPackage classifies a component-store package name.
//
// The format is Name~PublisherKey~Architecture~Language~Version, and the
// interesting part is that only some names carry a KB:
//
//	Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.33296.1.21
//	Package_for_ServicingStack_33288~31bf3856ad364e35~amd64~~26100.33288.1.4
//	Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9344.1
//	Package_for_KB5054156~31bf3856ad364e35~amd64~~26100.1.1.0
//	Package_10_for_KB5120708~31bf3856ad364e35~amd64~~10.0.9344.1
//
// Returns false for the thousands of inbox components, language packs and
// features on demand that are not updates at all.
func parseServicingPackage(name string) (servicing, bool) {
	fields := strings.Split(name, "~")
	if len(fields) < 5 {
		return servicing{}, false
	}
	identity, version := fields[0], fields[len(fields)-1]

	switch {
	case strings.HasPrefix(identity, "Package_for_RollupFix"):
		return servicing{Kind: KindCumulative, Version: buildAndUBR(version), Identity: name}, true

	case strings.HasPrefix(identity, "Package_for_ServicingStack"):
		return servicing{Kind: KindServicingStack, Version: buildAndUBR(version), Identity: name}, true

	case strings.HasPrefix(identity, "Package_for_DotNetRollup"):
		return servicing{Kind: KindDotNetRollup, Version: version, Identity: name}, true

	case kbFromCBSPackage(identity) != "":
		// Both "Package_for_KB..." and the "Package_N_for_KB..." children a
		// rollup installs. The caller collapses the children onto their KB.
		return servicing{Kind: KindStandalone, KB: kbFromCBSPackage(identity), Identity: name}, true
	}
	return servicing{}, false
}

// buildAndUBR trims a package version to the two components that identify a
// Windows patch level: 26100.33296.1.21 becomes 26100.33296, which is exactly
// what CurrentBuild and UBR report.
func buildAndUBR(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return version
	}
	return parts[0] + "." + parts[1]
}
