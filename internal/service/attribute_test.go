package service

import (
	"strings"
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

// inventory is the fallback join: components that recorded the executable as
// one of their own locations. The package-database join is exercised
// separately, because on Linux it is the only one that fires.
func inventory() Inventory {
	return Inventory{Components: []model.Component{
		{Name: "nginx", Version: "1.24.0-2", Type: "deb",
			PURL:      "pkg:deb/ubuntu/nginx@1.24.0-2",
			Locations: []string{"/usr/sbin/nginx", "/var/lib/dpkg/status"}},
		{Name: "postgresql-18", Version: "18.4", Type: "deb",
			PURL:      "pkg:deb/ubuntu/postgresql-18@18.4",
			Locations: []string{"/usr/lib/postgresql/18/bin/postgres"}},
	}}
}

func svc(exe string, port uint16) Service {
	return Service{
		Process:   Process{PID: 100, Exe: exe, Unit: "nginx.service"},
		Endpoints: []Endpoint{{Protocol: TCP, Address: "0.0.0.0", Port: port, Inode: 1}},
	}
}

// High confidence is the case where an installed package owns the executable:
// the product and version are known, not inferred.
func TestAttributeHighConfidence(t *testing.T) {
	got := Attribute([]Service{svc("/usr/sbin/nginx", 443)}, inventory(), 0)
	if len(got) != 1 {
		t.Fatalf("got %d services", len(got))
	}
	s := got[0]
	if s.Confidence != model.ConfidenceHigh {
		t.Errorf("confidence = %q, want high", s.Confidence)
	}
	if len(s.Components) != 1 || s.Components[0] != "pkg:deb/ubuntu/nginx@1.24.0-2" {
		t.Errorf("components = %v", s.Components)
	}
	if len(s.Endpoints) != 1 || s.Endpoints[0] != "0.0.0.0:443/tcp" {
		t.Errorf("endpoints = %v", s.Endpoints)
	}
	if len(s.Evidence) == 0 {
		t.Error("no evidence recorded for a high-confidence finding")
	}
}

// Medium confidence is the finding that matters most: software serving traffic
// that no package manager installed, which a package inventory cannot see.
func TestAttributeUnmanagedSoftware(t *testing.T) {
	got := Attribute([]Service{svc("/opt/vendor/appserver", 8080)}, inventory(), 0)
	s := got[0]
	if s.Confidence != model.ConfidenceMedium {
		t.Errorf("confidence = %q, want medium", s.Confidence)
	}
	if len(s.Components) != 0 {
		t.Errorf("components = %v, want none", s.Components)
	}
	if !containsSubstring(s.Evidence, "no installed package owns") {
		t.Errorf("evidence does not say why: %v", s.Evidence)
	}
}

// A containerised process's executable path is in the container's namespace.
// Matching it against host components attributes the container's service to
// whatever the host has at that path -- a wrong answer, not a missing one.
func TestAttributeDoesNotMatchContainerPathsAgainstTheHost(t *testing.T) {
	s := svc("/usr/sbin/nginx", 8443)
	s.Process.Container = "9d5a98d0dc04"
	s.Process.Isolated = true

	got := Attribute([]Service{s}, inventory(), 0)[0]
	if len(got.Components) != 0 {
		t.Errorf("a container's service was attributed to a host package: %v", got.Components)
	}
	if got.Confidence != model.ConfidenceMedium {
		t.Errorf("confidence = %q, want medium", got.Confidence)
	}
	if !containsSubstring(got.Evidence, "container's filesystem") {
		t.Errorf("evidence does not explain the refusal: %v", got.Evidence)
	}
}

// The bug this guard exists for. Under the cgroupfs driver a container's
// cgroup carries no runtime prefix and no ".scope", so no container id is
// recognised -- and before the mount namespace was consulted, the container's
// /usr/sbin/nginx was matched against the *host's* nginx package and reported
// with the highest confidence. Wrong package, wrong version, stated firmly.
func TestAttributeRefusesAnIsolatedProcessWithNoContainerID(t *testing.T) {
	s := svc("/usr/sbin/nginx", 8443)
	s.Process.Isolated = true // no Container: the cgroup layout was not recognised

	got := Attribute([]Service{s}, inventory(), 0)[0]
	if len(got.Components) != 0 {
		t.Errorf("an isolated process was attributed to a host package: %v", got.Components)
	}
	if got.Confidence != model.ConfidenceMedium {
		t.Errorf("confidence = %q, want medium", got.Confidence)
	}
	if !containsSubstring(got.Evidence, "another mount namespace") {
		t.Errorf("evidence does not explain the refusal: %v", got.Evidence)
	}
}

// init holding the socket means the daemon may not be running at all.
func TestAttributeSocketActivated(t *testing.T) {
	s := svc("/usr/lib/systemd/systemd", 22)
	s.SocketActivated = true

	got := Attribute([]Service{s}, inventory(), 0)[0]
	if got.Confidence != model.ConfidenceLow {
		t.Errorf("confidence = %q, want low", got.Confidence)
	}
	if len(got.Components) != 0 {
		t.Errorf("a socket-activated port was attributed to software: %v", got.Components)
	}
	if !containsSubstring(got.Evidence, "socket-activated") {
		t.Errorf("evidence = %v", got.Evidence)
	}
}

// Sockets nobody could be found for become one entry, not one each: they share
// a cause, and separate entries would suggest something distinct was learned
// about each.
func TestAttributeSummarisesUnattributedSockets(t *testing.T) {
	got := Attribute(nil, inventory(), 38)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 summary", len(got))
	}
	if got[0].Confidence != model.ConfidenceLow {
		t.Errorf("confidence = %q, want low", got[0].Confidence)
	}
	if !containsSubstring(got[0].Evidence, "38 listening socket") {
		t.Errorf("evidence = %v", got[0].Evidence)
	}
}

func containsSubstring(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// The join that actually fires on a Linux host: an OS package records
// /var/lib/dpkg/status as its location and never /usr/sbin/sshd, so only the
// package database can say who owns the executable. Before this existed, every
// daemon on a stock server reported as software no package manager installed.
func TestAttributePrefersThePackageDatabase(t *testing.T) {
	inv := inventory()
	inv.FileOwners = map[string][]string{
		"/usr/sbin/sshd": {"pkg:deb/ubuntu/openssh-server@1:9.6p1-3"},
	}

	got := Attribute([]Service{svc("/usr/sbin/sshd", 22)}, inv, 0)[0]
	if got.Confidence != model.ConfidenceHigh {
		t.Errorf("confidence = %q, want high", got.Confidence)
	}
	if len(got.Components) != 1 || got.Components[0] != "pkg:deb/ubuntu/openssh-server@1:9.6p1-3" {
		t.Errorf("components = %v", got.Components)
	}
	if !containsSubstring(got.Evidence, "package database records") {
		t.Errorf("evidence does not name its source: %v", got.Evidence)
	}
}

// A path nobody was asked about and a path nobody owns must not look the same:
// the probe answers only what it was given, and an absent entry means "no
// package owns this", which is a finding.
func TestAttributeFallsBackToLocationsWhenTheDatabaseIsSilent(t *testing.T) {
	inv := inventory()
	inv.FileOwners = map[string][]string{"/usr/sbin/sshd": {"pkg:deb/ubuntu/openssh-server@1:9.6p1-3"}}

	got := Attribute([]Service{svc("/usr/sbin/nginx", 443)}, inv, 0)[0]
	if got.Confidence != model.ConfidenceHigh {
		t.Errorf("confidence = %q, want high", got.Confidence)
	}
	if !containsSubstring(got.Evidence, "where the inventory found") {
		t.Errorf("evidence = %v", got.Evidence)
	}
}

// ExePaths is what the scan is asked to resolve. Handing it a containerised
// process's path would ask the host's package databases about a path in
// another mount namespace.
func TestExePathsSkipsWhatCannotBeJoined(t *testing.T) {
	contained := svc("/usr/sbin/nginx", 8443)
	contained.Process.Container = "9d5a98d0dc04"
	contained.Process.Isolated = true
	activated := svc("/usr/lib/systemd/systemd", 22)
	activated.SocketActivated = true

	r := &Result{Services: []Service{
		svc("/usr/sbin/sshd", 22),
		svc("/usr/sbin/sshd", 22), // same binary, second listener
		contained,
		activated,
		{Endpoints: []Endpoint{{Protocol: TCP, Port: 9000}}}, // no exe
	}}

	got := r.ExePaths()
	if len(got) != 1 || got[0] != "/usr/sbin/sshd" {
		t.Errorf("ExePaths() = %v, want [/usr/sbin/sshd]", got)
	}
}
