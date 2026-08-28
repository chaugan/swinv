package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

// fakeRoot builds a tree with the given files, each holding the given bytes.
// A value of "" creates an empty file; a path ending in "/" creates a
// directory.
func fakeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(rel, "/")))
		if strings.HasSuffix(rel, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func statusFor(t *testing.T, root string, counts map[string]int) map[string]model.SourceStatus {
	t.Helper()
	return sourceStatuses(probeSources(root, knownSourceProbes()), counts)
}

// TestAbsentDatabaseIsSkippedNotFailed: a host with no rpmdb is a fact about
// the host, and the reason has to say so.
func TestAbsentDatabaseIsSkippedNotFailed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the probed databases are Unix package databases")
	}
	root := fakeRoot(t, map[string]string{"var/lib/dpkg/status": "Package: bash\n"})

	got := statusFor(t, root, map[string]int{"dpkg": 3})

	if got["dpkg"].Status != model.SourceOK || got["dpkg"].Components != 3 {
		t.Errorf("dpkg = %+v, want ok with 3 components", got["dpkg"])
	}
	rpm := got["rpm"]
	if rpm.Status != model.SourceSkipped {
		t.Errorf("rpm = %+v, want skipped", rpm)
	}
	if !strings.Contains(rpm.Reason, "rpm package database") {
		t.Errorf("rpm reason = %q, want it to name what is absent", rpm.Reason)
	}
}

// TestUnreadableDatabaseIsAnError is the whole point of probing at all: a
// package database that exists and cannot be read produces the same empty
// component list as a host that never had one.
func TestUnreadableDatabaseIsAnError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can read a 0000 file")
	}
	root := fakeRoot(t, map[string]string{"var/lib/dpkg/status": "Package: bash\n"})
	target := filepath.Join(root, "var/lib/dpkg/status")
	if err := os.Chmod(target, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(target, 0o644) })

	got := statusFor(t, root, map[string]int{})["dpkg"]
	if got.Status != model.SourceError {
		t.Fatalf("dpkg = %+v, want an error: an unreadable package database is exactly "+
			"how a host with 4,000 packages reports 15", got)
	}
	if !strings.Contains(got.Reason, target) {
		t.Errorf("reason = %q, want it to name the path an operator has to fix", got.Reason)
	}
	if names := model.FailedSources(map[string]model.SourceStatus{"dpkg": got}); len(names) != 1 {
		t.Errorf("FailedSources = %v, want [dpkg]", names)
	}
}

// TestReadableDatabaseThatYieldedNothingIsAnError. Present, not empty, and no
// packages came out of it: the file is fine and the scan is not.
func TestReadableDatabaseThatYieldedNothingIsAnError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the probed databases are Unix package databases")
	}
	root := fakeRoot(t, map[string]string{"var/lib/dpkg/status": "Package: bash\nVersion: 5.2\n"})

	got := statusFor(t, root, map[string]int{})["dpkg"]
	if got.Status != model.SourceError {
		t.Errorf("dpkg = %+v, want an error", got)
	}
	if !strings.Contains(got.Reason, "no packages") {
		t.Errorf("reason = %q, want it to say enumeration returned nothing", got.Reason)
	}
}

// TestEmptyDatabaseIsSkippedNotFailed. A zero-byte dpkg status is a container
// base image, not a failure, and calling it one would make --root on a minimal
// tree exit non-zero for no reason.
func TestEmptyDatabaseIsSkippedNotFailed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the probed databases are Unix package databases")
	}
	root := fakeRoot(t, map[string]string{"var/lib/dpkg/status": ""})

	got := statusFor(t, root, map[string]int{})["dpkg"]
	if got.Status != model.SourceSkipped {
		t.Errorf("dpkg = %+v, want skipped", got)
	}
	if !strings.Contains(got.Reason, "empty") {
		t.Errorf("reason = %q, want it to say the database is empty", got.Reason)
	}
}

// TestEmptyRpmDirectoryIsSkipped covers the directory-shaped probe.
func TestEmptyRpmDirectoryIsSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the probed databases are Unix package databases")
	}
	root := fakeRoot(t, map[string]string{"var/lib/rpm/": ""})

	got := statusFor(t, root, map[string]int{})["rpm"]
	if got.Status != model.SourceSkipped || !strings.Contains(got.Reason, "empty") {
		t.Errorf("rpm = %+v, want skipped because empty", got)
	}
}

// TestSourceKeyNamesEverySourceExactlyOnce. The mapped catalogers collapse
// onto their probe's name; everything else keeps its own, so a Syft release
// that adds a cataloger nobody mapped still reports a real count under a real
// name instead of vanishing.
func TestSourceKeyNamesEverySourceExactlyOnce(t *testing.T) {
	cases := map[string]string{
		"dpkg-db-cataloger":                  "dpkg",
		"rpm-db-cataloger":                   "rpm",
		"apk-db-cataloger":                   "apk",
		"javascript-package-cataloger":       "javascript-package",
		"python-installed-package-cataloger": "python-installed-package",
		"container-runtime-probe":            "container-runtime-probe",
		"a-brand-new-cataloger":              "a-brand-new",
		"":                                   "unattributed",
	}
	for in, want := range cases {
		if got := sourceKey(in); got != want {
			t.Errorf("sourceKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEverySourceStatusCarriesAReasonUnlessItWorked. "skipped" with no reason
// tells a reader something did not happen and gives them nothing to do.
func TestEverySourceStatusCarriesAReasonUnlessItWorked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the probed databases are Unix package databases")
	}
	root := fakeRoot(t, map[string]string{"var/lib/dpkg/status": "Package: bash\n"})

	for name, s := range statusFor(t, root, map[string]int{"dpkg": 1}) {
		if s.Status != model.SourceOK && strings.TrimSpace(s.Reason) == "" {
			t.Errorf("source %q is %q with no reason", name, s.Status)
		}
	}
}

// TestComponentCountsAddUpToTheInventory. The receiver checks this; so does
// the collector, first.
func TestComponentCountsAddUpToTheInventory(t *testing.T) {
	components := []model.Component{
		{Name: "bash", FoundBy: "dpkg-db-cataloger"},
		{Name: "coreutils", FoundBy: "dpkg-db-cataloger"},
		{Name: "left-pad", FoundBy: "javascript-package-cataloger"},
		{Name: "mystery", FoundBy: ""},
	}
	counts := componentsBySource(components)
	sources := sourceStatuses(nil, counts)

	if total := model.SourceComponentTotal(sources); total != len(components) {
		t.Errorf("sources account for %d of %d components", total, len(components))
	}
	if counts["unattributed"] != 1 {
		t.Errorf("a component with no found_by was not counted anywhere: %v", counts)
	}
}

// Issue #15: the source field on a component must be the exact manifest key,
// including the cases where found_by does not map by stripping "-cataloger".
func TestSourceKeyMatchesManifestVocabulary(t *testing.T) {
	cases := map[string]string{
		"dpkg-db-cataloger":           "dpkg",
		"windows-pe-cataloger":        "windows-pe",
		"language-manifest-cataloger": "language-manifest",
		"container-runtime-probe":     "container-runtime-probe",
		"":                            "unattributed",
	}
	for foundBy, want := range cases {
		if got := sourceKey(foundBy); got != want {
			t.Errorf("sourceKey(%q) = %q, want %q", foundBy, got, want)
		}
	}
}
