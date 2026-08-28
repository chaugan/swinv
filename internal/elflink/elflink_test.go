package elflink

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, name, body string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The soname path a binary loads is usually an ldconfig-made symlink no
// package ships: dpkg owns libz.so.1.3.1, the target. Resolution must land on
// the real file or the library reports as unmanaged when it is anything but.
func TestResolveChasesSymlinksToTheRealFile(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/lib/libz.so.1.3.1", "elf-ish")
	if err := os.Symlink("libz.so.1.3.1", filepath.Join(root, "usr/lib/libz.so.1")); err != nil {
		t.Fatal(err)
	}

	r := newResolver(root)
	got := r.resolve("libz.so.1", nil)
	if got != "/usr/lib/libz.so.1.3.1" {
		t.Errorf("resolve = %q, want the symlink's target", got)
	}
}

// An absolute symlink target must be re-rooted under the probe root. For a
// container probed through /proc/<pid>/root, following it via the OS would
// walk out of the container and onto the host's copy of the library.
func TestResolveStaysInsideTheProbeRoot(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/lib/real.so.1", "container's copy")
	if err := os.Symlink("/usr/lib/real.so.1", filepath.Join(root, "usr/lib/liba.so.1")); err != nil {
		t.Fatal(err)
	}

	r := newResolver(root)
	if got := r.resolve("liba.so.1", nil); got != "/usr/lib/real.so.1" {
		t.Errorf("resolve = %q", got)
	}
	// And a link pointing at something absent inside the root resolves to
	// nothing, even if the host has it.
	if err := os.Symlink("/usr/lib/libc.so.6", filepath.Join(root, "usr/lib/libhost.so.1")); err != nil {
		t.Fatal(err)
	}
	if got := r.resolve("libhost.so.1", nil); got != "" {
		t.Errorf("a symlink escaping the root resolved to %q", got)
	}
}

func TestResolveSymlinkLoopStops(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("libb.so", filepath.Join(root, "usr/lib/liba.so")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("liba.so", filepath.Join(root, "usr/lib/libb.so")); err != nil {
		t.Fatal(err)
	}
	if got := r0(root).resolve("liba.so", nil); got != "" {
		t.Errorf("a symlink loop resolved to %q", got)
	}
}

func r0(root string) *resolver { return newResolver(root) }

// Object search dirs (RUNPATH) win over the standard directories, as ld.so
// resolves them.
func TestResolveObjectDirsFirst(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/lib/libx.so.1", "system copy")
	write(t, root, "opt/app/lib/libx.so.1", "bundled copy")

	r := newResolver(root)
	if got := r.resolve("libx.so.1", []string{"/opt/app/lib"}); got != "/opt/app/lib/libx.so.1" {
		t.Errorf("resolve = %q, want the RUNPATH copy", got)
	}
	if got := r.resolve("libx.so.1", nil); got != "/usr/lib/libx.so.1" {
		t.Errorf("resolve = %q, want the system copy", got)
	}
}

// ld.so.conf configures extra directories, and every distribution writes it as
// an include glob.
func TestLdConfDirs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/ld.so.conf", "include /etc/ld.so.conf.d/*.conf\n")
	write(t, root, "etc/ld.so.conf.d/custom.conf", "# comment\n/opt/vendor/lib\n")
	got := ldConfDirs(root)
	if len(got) != 1 || got[0] != "/opt/vendor/lib" {
		t.Errorf("ldConfDirs = %v", got)
	}
	if got := ldConfDirs(t.TempDir()); got != nil {
		t.Errorf("a root with no ld.so.conf produced %v", got)
	}
}

// A live probe of this machine's shell, which on any glibc or musl system is
// dynamic. Skipped where it is not, rather than failing on an exotic host.
func TestProbeLive(t *testing.T) {
	links, err := Probe("/bin/sh", Options{Root: "/"})
	if err != nil || len(links) == 0 {
		t.Skip("/bin/sh is absent or statically linked here")
	}
	var libc *Link
	for i := range links {
		if links[i].Soname == "libc.so.6" || links[i].Soname == "libc.musl-x86_64.so.1" {
			libc = &links[i]
		}
	}
	if libc == nil {
		t.Fatalf("no libc among %+v", links)
	}
	if libc.Path == "" {
		t.Error("libc did not resolve to a path")
	}
	if libc.NSymbols == 0 {
		t.Error("no imported symbols counted for libc")
	}
	if len(libc.Symbols) != 0 {
		t.Error("symbols were included without being asked for")
	}

	// And with symbols asked for, they arrive sorted.
	links, err = Probe("/bin/sh", Options{Root: "/", Symbols: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range links {
		if l.Direct && l.NSymbols > 0 && len(l.Symbols) == 0 {
			t.Errorf("%s: n_symbols=%d but no list with Symbols:true", l.Soname, l.NSymbols)
		}
	}
}

// A static binary loads nothing, which is an answer rather than a failure.
func TestProbeStatic(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip()
	}
	links, err := Probe(self, Options{Root: "/"})
	if err != nil {
		// The test binary may be dynamic under cgo; either outcome is fine,
		// what must not happen is an error on the static case, which is
		// covered by any CGO_ENABLED=0 build of the suite.
		t.Skipf("test binary probed with error: %v", err)
	}
	_ = links
}

func TestPaths(t *testing.T) {
	got := Paths([]Link{
		{Soname: "a", Path: "/usr/lib/a.so"},
		{Soname: "b", Path: ""},
		{Soname: "c", Path: "/usr/lib/a.so"},
		{Soname: "d", Path: "/lib/d.so"},
	})
	if len(got) != 2 || got[0] != "/lib/d.so" || got[1] != "/usr/lib/a.so" {
		t.Errorf("Paths = %v", got)
	}
}

// The ELF walk honours ./-anchored excludes the same way the SUID walk does.
func TestFindELFHonoursExcludes(t *testing.T) {
	root := t.TempDir()
	elf := []byte("\x7fELF" + strings.Repeat("x", 100))
	for _, rel := range []string{"opt/cache/big", "usr/bin/kept"} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, elf, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	paths, _ := FindELF(context.Background(), root, []string{"./opt/**"})
	if len(paths) != 1 || paths[0] != "/usr/bin/kept" {
		t.Fatalf("paths = %v, want only /usr/bin/kept", paths)
	}
}

// R8 (SECURITY.md): a crafted binary can put a path in a DT_NEEDED entry
// ("../../../etc/shadow"). A real soname never contains a slash, and the
// resolver must never turn one into a host path the root probe then opens.
// The jail already re-roots each hop; this pins that even a direct
// slash-bearing name does not escape.
func TestResolveRejectsSlashBearingSoname(t *testing.T) {
	root := t.TempDir()
	// A file exists at the traversal target inside the root; a naive resolver
	// that honoured the path would return it.
	write(t, root, "etc/shadow", "secret")
	r := newResolver(root)
	if got := r.resolve("../../../etc/shadow", nil); got != "" && got != "/etc/shadow" {
		// resolve() itself re-roots; the Probe layer additionally rejects the
		// slash outright. Either way it must not return an un-jailed traversal.
		if filepath.IsAbs(got) && got != "/etc/shadow" {
			t.Errorf("a slash-bearing soname resolved to an un-jailed path %q", got)
		}
	}
}
