package main

// knownSourceProbes is empty on Windows.
//
// The Windows inventory comes from the registry, the side-by-side store and PE
// version resources, none of which is a file whose presence or absence can be
// checked the way a package database can. Reporting the Unix probes here would
// fill every Windows manifest with four sources skipped for reasons that were
// never true of the platform, which is worse than saying nothing: it teaches
// an operator to ignore the sources block.
//
// The counted sources -- windows-registry, windows-pe, windows-appx and the
// rest -- still appear, because they are derived from the components
// themselves rather than from a probe.
func knownSourceProbes() []sourceProbe { return nil }
