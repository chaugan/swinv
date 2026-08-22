package service

import (
	"fmt"
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// Inventory is what the attribution joins against.
type Inventory struct {
	// FileOwners maps an executable path to the identities of the packages
	// whose own database says they installed it. This is the authoritative
	// source and the only one that works for OS packages, whose recorded
	// locations are their evidence files rather than their contents.
	FileOwners map[string][]string

	// Components is the full inventory, consulted where FileOwners has
	// nothing. It covers what the package databases do not: a Windows
	// registry entry pointing at its own executable, and a binary the file
	// catalogers identified directly.
	Components []model.Component
}

// Attribute turns collected services into report entries, joining each
// listening executable to the installed software that owns it.
//
// The join is the point of the whole exercise. A package database says what is
// installed; this says which of it is actually serving, and -- more usefully --
// which serving software nothing installed accounts for.
func Attribute(services []Service, inv Inventory, unattributed int) []model.Service {
	owners := indexByLocation(inv.Components)

	out := make([]model.Service, 0, len(services)+1)
	for _, s := range services {
		out = append(out, attributeOne(s, inv.FileOwners, owners))
	}

	// The sockets nobody could be found for are one entry, not one each: they
	// share a single cause and listing them separately would suggest the scan
	// learned something distinct about each.
	if unattributed > 0 {
		out = append(out, model.Service{
			Confidence: model.ConfidenceLow,
			Evidence: []string{fmt.Sprintf(
				"%d listening socket(s) could not be attributed to a process; "+
					"reading another user's open files requires root", unattributed)},
		})
	}
	return out
}

func attributeOne(s Service, fileOwners map[string][]string, owners map[string][]model.Component) model.Service {
	out := model.Service{
		PID:             s.Process.PID,
		Executable:      s.Process.Exe,
		Command:         s.Process.Command,
		Unit:            s.Process.Unit,
		Container:       s.Process.Container,
		User:            s.Process.User,
		SocketActivated: s.SocketActivated,
	}
	for _, e := range s.Endpoints {
		out.Endpoints = append(out.Endpoints, e.String())
		out.Evidence = append(out.Evidence, fmt.Sprintf("socket %s held by pid %d", e, s.Process.PID))
	}

	switch {
	case s.SocketActivated:
		// init holds the socket. The service that will answer has not been
		// identified and may not be running, so claiming otherwise would be
		// the confident wrong answer this design exists to avoid.
		out.Confidence = model.ConfidenceLow
		out.Evidence = append(out.Evidence,
			"the socket is held by init, so this is socket-activated and the "+
				"serving process has not been identified")
		return out

	case s.Process.Exe == "":
		out.Confidence = model.ConfidenceLow
		out.Evidence = append(out.Evidence, "the executable could not be read")
		return out
	}

	out.Evidence = append(out.Evidence, "executable "+s.Process.Exe)
	if s.Process.Unit != "" {
		out.Evidence = append(out.Evidence, "systemd unit "+s.Process.Unit)
	}
	if s.Process.Container != "" {
		out.Evidence = append(out.Evidence, "runs in container "+s.Process.Container)
	}

	// An isolated process's executable path belongs to another mount namespace,
	// so matching it against host components would attribute that workload's
	// service to whatever this host happens to have at the same path. A wrong
	// answer, not a missing one.
	//
	// Keyed on the mount namespace rather than on having recognised a container
	// id, because the id depends on knowing every runtime's cgroup layout and
	// the guard must not depend on that. See Process.Isolated.
	if s.Process.Isolated {
		out.Confidence = model.ConfidenceMedium
		where := "another mount namespace"
		if s.Process.Container != "" {
			where = "the container's filesystem"
		}
		out.Evidence = append(out.Evidence,
			"not matched against installed software: the path belongs to "+
				where+", not this host's")
		return out
	}

	// The package database first: it is the only source that can answer for an
	// OS package, and it answers exactly, from the package's own file list.
	if ids := fileOwners[s.Process.Exe]; len(ids) > 0 {
		out.Components = append([]string(nil), ids...)
		out.Confidence = model.ConfidenceHigh
		out.Evidence = append(out.Evidence,
			"the package database records "+strings.Join(ids, ", ")+" as owning this file")
		return out
	}

	// Failing that, a component that recorded this exact path as one of its
	// locations -- a Windows registry entry naming its own executable, or a
	// binary a file cataloger identified in place.
	if matches := owners[lookupKey(s.Process.Exe)]; len(matches) > 0 {
		for _, c := range matches {
			out.Components = append(out.Components, model.Identify(c))
		}
		out.Components = model.SortedSet(out.Components)
		out.Confidence = model.ConfidenceHigh
		out.Evidence = append(out.Evidence,
			"this file is where the inventory found "+strings.Join(out.Components, ", "))
		return out
	}

	// Then the directory a product was installed into. A Windows registry
	// entry records InstallLocation -- "C:\Program Files\7-Zip" -- and never
	// the executables under it, so nothing above can ever match on Windows
	// and every listener would report as unmanaged software.
	//
	// Weaker evidence than a package's own file list, and graded as such: a
	// containing directory says the product was installed there, not that it
	// ships this particular file.
	if ids, dir := containingProduct(s.Process.Exe, owners); len(ids) > 0 {
		out.Components = ids
		out.Confidence = model.ConfidenceMedium
		out.Evidence = append(out.Evidence, fmt.Sprintf(
			"installed under %s, which belongs to %s", dir, strings.Join(ids, ", ")))
		return out
	}

	// An operating-system component. Not "software nothing installed": it came
	// with the operating system, which swinv represents by the installed
	// servicing updates rather than file by file.
	if IsOSComponent(s.Process.Exe) {
		out.OSComponent = true
		out.Confidence = model.ConfidenceMedium
		out.Evidence = append(out.Evidence,
			"an operating-system component, which this inventory represents by the "+
				"installed updates rather than file by file, so no component owns it")
		return out
	}

	out.Confidence = model.ConfidenceMedium
	out.Evidence = append(out.Evidence,
		"no installed package owns this executable, so it was not installed "+
			"by a package manager")
	return out
}

// containingProduct finds the installed product whose recorded location is the
// directory this executable sits under.
//
// The longest matching directory wins, which is what keeps
// "C:\Program Files\Adobe\Adobe Photoshop 2024\x.exe" attributed to
// Photoshop rather than to whatever else recorded "C:\Program Files\Adobe".
// A tie is reported as a tie: two products claiming the same directory are two
// candidates, not a coin flip.
func containingProduct(exe string, owners map[string][]model.Component) ([]string, string) {
	if exe == "" {
		return nil, ""
	}
	sep := "/"
	if strings.Contains(exe, "\\") {
		sep = "\\"
	}
	key := lookupKey(exe)

	var best string
	for dir := range owners {
		if len(dir) >= len(key) || !strings.HasPrefix(key, dir+sep) {
			continue
		}
		if len(dir) > len(best) {
			best = dir
		}
	}
	if best == "" {
		return nil, ""
	}

	var ids []string
	for _, c := range owners[best] {
		ids = append(ids, model.Identify(c))
	}
	return model.SortedSet(ids), best
}

// lookupKey normalises a path for comparison against recorded locations.
// Windows paths are case-insensitive, and the registry and the process table
// disagree about case often enough that an exact comparison misses.
func lookupKey(p string) string {
	if pathsAreCaseInsensitive() {
		return strings.ToLower(p)
	}
	return p
}

// indexByLocation maps every recorded file location to the components claiming
// it, so an executable path can be looked up directly.
func indexByLocation(components []model.Component) map[string][]model.Component {
	out := make(map[string][]model.Component)
	for _, c := range components {
		for _, loc := range c.Locations {
			out[lookupKey(loc)] = append(out[lookupKey(loc)], c)
		}
	}
	return out
}
