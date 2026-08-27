package pelink

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildPE cross-compiles a minimal real PE binary. Go's own linker gives the
// test a genuine import table - kernel32.dll, with real function names - so
// the parser is proved against the file format, not against a synthetic.
func buildPE(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "probe-me.exe")
	cmd := exec.Command("go", "build", "-o", exe, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot cross-compile a PE fixture: %v\n%s", err, out)
	}
	return exe
}

func TestProbeReadsARealImportTable(t *testing.T) {
	exe := buildPE(t)
	links, err := Probe(exe, Options{Symbols: true, SystemDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(links) == 0 {
		t.Fatal("a Go-built PE imports kernel32.dll; the probe found nothing")
	}

	var k32 *Link
	for i := range links {
		if strings.EqualFold(links[i].Name, "kernel32.dll") {
			k32 = &links[i]
		}
	}
	if k32 == nil {
		t.Fatalf("kernel32.dll is not among the imports: %+v", links)
	}
	if !k32.Direct {
		t.Error("kernel32.dll import is not marked direct")
	}
	if k32.NSymbols == 0 || len(k32.Symbols) == 0 {
		t.Errorf("no imported functions recorded: %+v", k32)
	}
	found := false
	for _, s := range k32.Symbols {
		if s == "ExitProcess" || s == "WriteFile" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected well-known kernel32 imports, got %v", k32.Symbols[:min(5, len(k32.Symbols))])
	}
	if k32.Path != "" {
		t.Errorf("kernel32.dll resolved to %q with an empty system dir", k32.Path)
	}
}

// A DLL present in the system directory resolves there, and the probe
// descends into it - proved by planting a real PE under the DLL's name.
func TestProbeResolvesAndDescends(t *testing.T) {
	exe := buildPE(t)
	sysDir := t.TempDir()
	fixture, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sysDir, "kernel32.dll"), fixture, 0o755); err != nil {
		t.Fatal(err)
	}

	links, err := Probe(exe, Options{SystemDir: sysDir})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range links {
		if strings.EqualFold(l.Name, "kernel32.dll") {
			if l.Path != filepath.Join(sysDir, "kernel32.dll") {
				t.Errorf("path = %q", l.Path)
			}
			return
		}
	}
	t.Fatal("kernel32.dll missing")
}

// The application's own directory outranks the system directory - the search
// order that makes DLL planting a real technique, reported as what would
// actually load.
func TestProbePrefersTheApplicationDirectory(t *testing.T) {
	exe := buildPE(t)
	appDir := filepath.Dir(exe)
	sysDir := t.TempDir()
	for _, dir := range []string{appDir, sysDir} {
		if err := os.WriteFile(filepath.Join(dir, "kernel32.dll"), []byte("not a pe"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	links, err := Probe(exe, Options{SystemDir: sysDir})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range links {
		if strings.EqualFold(l.Name, "kernel32.dll") {
			if l.Path != filepath.Join(appDir, "kernel32.dll") {
				t.Errorf("path = %q, want the application directory to win", l.Path)
			}
			return
		}
	}
	t.Fatal("kernel32.dll missing")
}

func TestProbeIgnoresNonPEFiles(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "server.py")
	if err := os.WriteFile(script, []byte("print('hi')\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	links, err := Probe(script, Options{})
	if err != nil || links != nil {
		t.Fatalf("a python script produced (%v, %v); a script with a port open is not an error", links, err)
	}
}

func TestIsAPISet(t *testing.T) {
	if !isAPISet("api-ms-win-crt-runtime-l1-1-0.dll") || !isAPISet("EXT-MS-WIN-something.dll") {
		t.Error("API set names not recognised")
	}
	if isAPISet("KERNEL32.dll") {
		t.Error("kernel32 is not an API set")
	}
}

// ProbeAll shares one parse cache across every binary. Two copies of the
// same PE must both produce links, and the fixture planted as their shared
// dependency is parsed once, not once per binary.
func TestProbeAllSharesTheCache(t *testing.T) {
	exe := buildPE(t)
	dir := t.TempDir()
	fixture, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(dir, "a.exe")
	b := filepath.Join(dir, "b.exe")
	sysDir := t.TempDir()
	for _, p := range []string{a, b, filepath.Join(sysDir, "kernel32.dll")} {
		if err := os.WriteFile(p, fixture, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	got := ProbeAll(t.Context(), []string{a, b, filepath.Join(dir, "not-pe.txt")},
		Options{SystemDir: sysDir}, 2)
	if len(got) != 2 {
		t.Fatalf("got links for %d of 2 binaries: %v", len(got), keys(got))
	}
	for _, path := range []string{a, b} {
		found := false
		for _, l := range got[path] {
			if strings.EqualFold(l.Name, "kernel32.dll") && l.Path != "" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: kernel32.dll not resolved: %+v", path, got[path])
		}
	}
}

func keys(m map[string][]Link) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestPolitePauseBounds(t *testing.T) {
	if politePause(0) != 200*time.Microsecond {
		t.Error("a cached parse must still yield the floor")
	}
	if politePause(2*time.Millisecond) != 2*time.Millisecond {
		t.Error("the pause should match the work")
	}
	if politePause(3*time.Second) != 25*time.Millisecond {
		t.Error("one slow file must not stall the probe for seconds")
	}
}
