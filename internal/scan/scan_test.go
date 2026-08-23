package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chaugan/swinv/internal/model"
)

// --- exclusion pattern validation ------------------------------------------

func TestValidatePattern(t *testing.T) {
	valid := []string{
		"./proc/**",
		"./swapfile",
		"*/node_modules/**",
		"**/*.iso",
		"./a/b/c/**",
	}
	for _, p := range valid {
		t.Run("valid/"+p, func(t *testing.T) {
			if err := ValidatePattern(p); err != nil {
				t.Errorf("ValidatePattern(%q) = %v, want nil", p, err)
			}
		})
	}

	invalid := []string{
		"",
		"   ",
		"/proc/**",     // absolute: Syft matches this against nothing
		"proc/**",      // bare relative
		"../escape/**", // does not start with an accepted prefix
		"~/thing",
		"*proc/**", // "*/" required, "*p" is not it
	}
	for _, p := range invalid {
		t.Run("invalid/"+p, func(t *testing.T) {
			err := ValidatePattern(p)
			if err == nil {
				t.Fatalf("ValidatePattern(%q) = nil, want an error", p)
			}
			if strings.TrimSpace(p) == "" {
				// An empty pattern gets its own message; it has no prefix to
				// correct, so only the "is empty" diagnosis is required.
				if !strings.Contains(err.Error(), "empty") {
					t.Errorf("error %q should say the pattern is empty", err)
				}
				return
			}
			// Otherwise the message must teach the rule, since this is a
			// user-facing usage error and the fix is not obvious.
			for _, want := range []string{"./", "*/", "**/"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention the required prefix %q", err, want)
				}
			}
		})
	}
}

// --- mountinfo parsing ------------------------------------------------------

func TestParseMountinfo(t *testing.T) {
	// Real-shaped lines. Field 5 is the mount point; the fs type follows the
	// lone "-" separator, after a variable number of optional fields.
	const table = `
23 28 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
24 28 0:23 / /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw
25 28 0:5 / /dev rw,nosuid,relatime shared:8 - devtmpfs udev rw,size=8123456k
28 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
30 28 0:29 / /tmp rw,nosuid,nodev shared:11 - tmpfs tmpfs rw
99 28 0:88 / /data rw,relatime shared:44 - ext4 /dev/sdb1 rw
100 28 0:89 / /srv/nfs rw,relatime shared:45 - nfs4 10.0.0.9:/export rw
101 28 0:90 / /mnt/win rw,relatime - cifs //server/share rw
102 28 0:91 / /mnt/my\040disk rw,relatime - nfs 10.0.0.8:/x rw
103 28 0:92 / /net rw,relatime - autofs systemd-1 rw
104 28 0:93 / /snap/core20/2866 ro,nodev,relatime shared:60 - squashfs /dev/loop3 ro
105 28 0:94 / /home/u/sshfs rw,nosuid,nodev - fuse.sshfs u@h:/ rw
106 28 0:95 / /var/lib/docker/overlay2/abc/merged rw,relatime - overlay overlay rw
malformed line with too few fields
107 28 0:96 / /noseparator rw,relatime nfs4 x rw
`
	got := ParseMountinfo(strings.NewReader(table))
	want := []string{
		"/proc",
		"/sys",
		"/dev",
		"/tmp",
		"/srv/nfs",
		"/mnt/win",
		"/mnt/my disk", // octal \040 must be unescaped
		"/net",
		"/snap/core20/2866",
		"/home/u/sshfs",
		"/var/lib/docker/overlay2/abc/merged",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseMountinfo:\n got %q\nwant %q", got, want)
	}
}

func TestParseMountinfoSkipsRootAndLocalFilesystems(t *testing.T) {
	const table = `28 1 259:2 / / rw shared:1 - overlay overlay rw
99 28 0:88 / /data rw shared:44 - ext4 /dev/sdb1 rw
100 28 0:89 / /boot/efi rw - vfat /dev/nvme0n1p1 rw
`
	got := ParseMountinfo(strings.NewReader(table))
	if len(got) != 0 {
		t.Errorf("got %q, want none: / must never be excluded and ext4/vfat are local", got)
	}
}

func TestParseMountinfoDeduplicates(t *testing.T) {
	const table = `30 28 0:29 / /tmp rw shared:11 - tmpfs tmpfs rw
31 28 0:30 / /tmp rw shared:12 - tmpfs tmpfs rw
`
	if got := ParseMountinfo(strings.NewReader(table)); len(got) != 1 {
		t.Errorf("got %q, want a single deduplicated entry", got)
	}
}

func TestParseMountinfoNilReader(t *testing.T) {
	if got := ParseMountinfo(nil); got != nil {
		t.Errorf("ParseMountinfo(nil) = %v, want nil", got)
	}
}

func TestUnescapeOctal(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/mnt/plain", "/mnt/plain"},
		{`/mnt/my\040disk`, "/mnt/my disk"},
		{`/mnt/a\011b`, "/mnt/a\tb"},
		{`/mnt/a\012b`, "/mnt/a\nb"},
		{`/mnt/a\134b`, `/mnt/a\b`},
		{`/mnt/trailing\`, `/mnt/trailing\`},
		{`/mnt/\999bad`, `/mnt/\999bad`}, // not valid octal, left alone
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := unescapeOctal(tt.in); got != tt.want {
				t.Errorf("unescapeOctal(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// --- exclusion assembly -----------------------------------------------------

func TestDefaultExcludesOnlyAppliesToRealRoot(t *testing.T) {
	got := DefaultExcludes("/")
	if len(got) == 0 {
		t.Fatal("DefaultExcludes(\"/\") is empty")
	}
	for _, want := range []string{"./proc/**", "./sys/**", "./var/cache/**", "./var/lib/docker/**", "./swapfile"} {
		if !contains(got, want) {
			t.Errorf("DefaultExcludes is missing %q", want)
		}
	}
	for _, p := range got {
		if err := ValidatePattern(p); err != nil {
			t.Errorf("generated default %q is not a valid pattern: %v", p, err)
		}
	}

	// An arbitrary tree has no known layout, so none of these apply.
	if got := DefaultExcludes("/some/fixture"); got != nil {
		t.Errorf("DefaultExcludes for a non-root tree = %v, want nil", got)
	}
}

func TestBuildExcludesComposition(t *testing.T) {
	dir := t.TempDir()
	mountinfo := filepath.Join(dir, "mountinfo")
	const table = `100 28 0:89 / /srv/nfs rw shared:45 - nfs4 10.0.0.9:/export rw
30 28 0:29 / /tmp rw shared:11 - tmpfs tmpfs rw
`
	if err := os.WriteFile(mountinfo, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}

	got, warnings, err := BuildExcludes(ExcludeOptions{
		Root:              "/",
		UserExcludes:      []string{"./custom/**"},
		AutoExcludeMounts: true,
		NoSnap:            true,
		NoFlatpak:         true,
		MountinfoPath:     mountinfo,
	})
	if err != nil {
		t.Fatalf("BuildExcludes: %v", err)
	}

	for _, want := range []string{
		"./proc/**",            // default
		"./srv/nfs/**",         // mount-derived
		"./snap/**",            // --no-snap
		"./var/lib/flatpak/**", // --no-flatpak
		"./custom/**",          // user
	} {
		if !contains(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if len(warnings) == 0 {
		t.Error("expected warnings explaining the automatic exclusions")
	}
}

func TestBuildExcludesIsSortedAndDeduplicated(t *testing.T) {
	got, _, err := BuildExcludes(ExcludeOptions{
		Root: "/",
		// "./proc/**" is already a default; supplying it again must not duplicate it.
		UserExcludes: []string{"./zzz/**", "./aaa/**", "./proc/**"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("not sorted at %d: %q then %q", i, got[i-1], got[i])
		}
		if got[i-1] == got[i] {
			t.Fatalf("duplicate entry %q", got[i])
		}
	}
}

// TestBuildExcludesIsDeterministic underwrites the byte-identical-output promise.
func TestBuildExcludesIsDeterministic(t *testing.T) {
	opts := ExcludeOptions{Root: "/", UserExcludes: []string{"./b/**", "./a/**"}}
	first, _, err := BuildExcludes(opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, _, err := BuildExcludes(opts)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differs:\n%v\n%v", i, first, again)
		}
	}
}

func TestBuildExcludesRejectsBadUserPattern(t *testing.T) {
	_, _, err := BuildExcludes(ExcludeOptions{Root: "/", UserExcludes: []string{"/absolute/**"}})
	if err == nil {
		t.Fatal("expected an error for an absolute user pattern")
	}
	if !strings.Contains(err.Error(), "/absolute/**") {
		t.Errorf("error %q should name the offending pattern", err)
	}
}

// TestBuildExcludesMissingMountinfoIsWarningNotError: an unreadable mount table
// makes the scan slower, never wrong.
func TestBuildExcludesMissingMountinfoIsWarningNotError(t *testing.T) {
	got, warnings, err := BuildExcludes(ExcludeOptions{
		Root:              "/",
		AutoExcludeMounts: true,
		MountinfoPath:     filepath.Join(t.TempDir(), "does-not-exist"),
	})
	if err != nil {
		t.Fatalf("BuildExcludes = %v, want nil error", err)
	}
	if len(got) == 0 {
		t.Error("defaults should still be present")
	}
	if len(warnings) == 0 {
		t.Error("expected a warning about the unreadable mount table")
	}
}

// TestBuildExcludesSkipsMountsOutsideRoot: an absolute mount point means
// nothing inside an unrelated fixture tree.
func TestBuildExcludesSkipsMountsOutsideRoot(t *testing.T) {
	dir := t.TempDir()
	mountinfo := filepath.Join(dir, "mountinfo")
	if err := os.WriteFile(mountinfo, []byte(
		"100 28 0:89 / /srv/nfs rw shared:45 - nfs4 10.0.0.9:/export rw\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _, err := BuildExcludes(ExcludeOptions{
		Root:              "/some/other/tree",
		AutoExcludeMounts: true,
		MountinfoPath:     mountinfo,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		if strings.Contains(p, "srv/nfs") {
			t.Errorf("mount outside the scan root leaked into the exclusions: %q", p)
		}
	}
}

// --- end-to-end scan against a fixture tree --------------------------------

// TestRunAgainstFixture is the integration check: a miniature rootfs must yield
// the packages it contains, with root-relative locations.
func TestRunAgainstFixture(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	result, err := Run(ctx, Options{Root: root, FileOwnership: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	byName := map[string]string{}
	for _, c := range result.Components {
		byName[c.Name] = c.Version
	}
	if got := byName["zlib1g"]; got != "1:1.2.13.dfsg-1" {
		t.Errorf("zlib1g version = %q, want 1:1.2.13.dfsg-1 (components: %v)", got, byName)
	}

	// Locations must be absolute system paths with the scan root stripped.
	for _, c := range result.Components {
		for _, loc := range c.Locations {
			if strings.HasPrefix(loc, root) {
				t.Errorf("location %q still carries the scan-root prefix %q", loc, root)
			}
			if !strings.HasPrefix(loc, "/") {
				t.Errorf("location %q is not an absolute path", loc)
			}
		}
	}

	if result.Distro == nil || result.Distro.ID != "debian" {
		t.Errorf("Distro = %+v, want ID debian", result.Distro)
	}
	if len(result.Catalogers) == 0 {
		t.Error("Catalogers should record the selection actually applied")
	}
}

// TestRunIsDeterministic: two scans of an unchanged tree agree exactly.
func TestRunIsDeterministic(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	first, err := Run(ctx, Options{Root: root, FileOwnership: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Run(ctx, Options{Root: root, FileOwnership: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Components, second.Components) {
		t.Errorf("two scans of the same tree produced different components (%d vs %d)",
			len(first.Components), len(second.Components))
	}
}

// TestRunCancelledContext: a cancelled context must be reported as such so the
// CLI can exit 4 rather than 3.
func TestRunCancelledContext(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := Run(ctx, Options{Root: root}); err == nil {
		t.Fatal("expected an error from an already-cancelled context")
	}
}

func TestSyftVersion(t *testing.T) {
	if got := SyftVersion(); got == "" {
		t.Error("SyftVersion() is empty; want a version or \"unknown\"")
	}
}

// --- helpers ----------------------------------------------------------------

func writeFixture(t *testing.T, root string) {
	t.Helper()
	files := map[string]string{
		"etc/os-release": "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
		"var/lib/dpkg/status": `Package: zlib1g
Status: install ok installed
Priority: required
Architecture: amd64
Version: 1:1.2.13.dfsg-1
Description: compression library - runtime

`,
	}
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// --- home directory policy --------------------------------------------------

// TestHomeExcludedByDefault covers the owner-visible default: user home trees
// are skipped unless --include-home is passed. This is what makes a full scan
// finish in a reasonable time; see homeExcludeDirs.
func TestHomeExcludedByDefault(t *testing.T) {
	byDefault, warnings, err := BuildExcludes(ExcludeOptions{Root: "/"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"./home/**", "./root/**"} {
		if !contains(byDefault, want) {
			t.Errorf("default exclusions are missing %q", want)
		}
	}
	if len(warnings) == 0 {
		t.Error("skipping home directories must be announced in a warning")
	}

	included, _, err := BuildExcludes(ExcludeOptions{Root: "/", IncludeHome: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"./home/**", "./root/**"} {
		if contains(included, unwanted) {
			t.Errorf("--include-home should not exclude %q", unwanted)
		}
	}
}

func TestHomeExcludesOnlyApplyToRealRoot(t *testing.T) {
	if got := HomeExcludes("/some/fixture"); got != nil {
		t.Errorf("HomeExcludes for a non-root tree = %v, want nil", got)
	}
}

// --- snap vs the squashfs mount rule ---------------------------------------

// TestSnapMountsSurviveTheSquashfsRule is the regression test for a genuine
// spec self-contradiction: snaps are squashfs loop mounts, so the "exclude
// non-local filesystems" rule would silently exclude every snap even though
// snaps are meant to be included by default, making --no-snap a no-op.
func TestSnapMountsSurviveTheSquashfsRule(t *testing.T) {
	dir := t.TempDir()
	mountinfo := filepath.Join(dir, "mountinfo")
	const table = `104 28 0:93 / /snap/core20/2866 ro,nodev shared:60 - squashfs /dev/loop3 ro
105 28 0:94 / /snap/snapd/27591 ro,nodev shared:61 - squashfs /dev/loop4 ro
106 28 0:95 / /var/lib/snapd/snap/firefox/1234 ro,nodev - squashfs /dev/loop5 ro
107 28 0:96 / /opt/images/appliance ro,nodev - squashfs /dev/loop9 ro
`
	if err := os.WriteFile(mountinfo, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}

	// Default: snaps stay in, unrelated squashfs images stay out.
	got, _, err := BuildExcludes(ExcludeOptions{
		Root: "/", AutoExcludeMounts: true, MountinfoPath: mountinfo,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{
		"./snap/core20/2866/**",
		"./snap/snapd/27591/**",
		"./var/lib/snapd/snap/firefox/1234/**",
	} {
		if contains(got, unwanted) {
			t.Errorf("snap mount %q was auto-excluded; snaps are installed software and are included by default", unwanted)
		}
	}
	if !contains(got, "./opt/images/appliance/**") {
		t.Error("a non-snap squashfs mount should still be excluded")
	}

	// --no-snap: now they go.
	withNoSnap, _, err := BuildExcludes(ExcludeOptions{
		Root: "/", AutoExcludeMounts: true, MountinfoPath: mountinfo, NoSnap: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(withNoSnap, "./snap/**") {
		t.Error("--no-snap must exclude ./snap/**")
	}
}

func TestIsSnapMount(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"/snap/core20/2866", true},
		{"/snap", true},
		{"/var/lib/snapd/snap/firefox/1234", true},
		{"/opt/images/appliance", false},
		{"/snapshot/backup", false}, // must not match on a bare prefix
		{"/mnt/snap", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := isSnapMount(tt.in); got != tt.want {
				t.Errorf("isSnapMount(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// --- symlink preflight ------------------------------------------------------

// TestQuarantineSymlinks is the regression test for the failure that produced a
// zero-component inventory on a real host: a readable symlink pointing into an
// unreadable directory makes Syft's indexer abort the entire scan.
func TestQuarantineSymlinks(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: no path is unreadable, so the failure cannot be reproduced")
	}

	root := t.TempDir()

	// An unreadable directory holding the symlink target, mirroring /root.
	secret := filepath.Join(root, "secret")
	if err := os.MkdirAll(filepath.Join(secret, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(secret, "inner", "python")
	if err := os.WriteFile(target, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o755) })

	// A readable symlink into it, mirroring the venv python that broke the scan.
	venv := filepath.Join(root, "opt", "app", "bin")
	if err := os.MkdirAll(venv, 0o755); err != nil {
		t.Fatal(err)
	}
	badLink := filepath.Join(venv, "python")
	if err := os.Symlink(target, badLink); err != nil {
		t.Fatal(err)
	}

	// A healthy symlink and a dangling one, neither of which should be touched.
	good := filepath.Join(root, "opt", "app", "real")
	if err := os.WriteFile(good, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(good, filepath.Join(venv, "good")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "nope"), filepath.Join(venv, "dangling")); err != nil {
		t.Fatal(err)
	}

	patterns, warnings := QuarantineSymlinks(context.Background(), root, nil)

	if !contains(patterns, "./opt/app/bin/python") {
		t.Errorf("the unresolvable symlink was not quarantined; got %v", patterns)
	}
	for _, unwanted := range []string{"./opt/app/bin/good", "./opt/app/bin/dangling"} {
		if contains(patterns, unwanted) {
			t.Errorf("%q should not be quarantined", unwanted)
		}
	}
	if len(warnings) == 0 {
		t.Error("quarantining a symlink must be announced in a warning")
	}
}

// TestQuarantineSymlinksHonoursExclusions: the preflight must not descend into
// trees the scan will skip anyway.
func TestQuarantineSymlinksHonoursExclusions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	root := t.TempDir()

	secret := filepath.Join(root, "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(secret, "thing")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o755) })

	skipped := filepath.Join(root, "skipme")
	if err := os.MkdirAll(skipped, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(skipped, "link")); err != nil {
		t.Fatal(err)
	}

	patterns, _ := QuarantineSymlinks(context.Background(), root, []string{"./skipme/**"})
	for _, p := range patterns {
		if strings.Contains(p, "skipme") {
			t.Errorf("preflight descended into an excluded tree: %q", p)
		}
	}
}

func TestQuarantineSymlinksCancelledContext(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Must return promptly without panicking.
	QuarantineSymlinks(ctx, root, nil)
}

// --- content hashing --------------------------------------------------------

func TestHashComponents(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("usr/bin/tool", "tool contents")
	write("srv/app/package.json", `{"name":"app"}`)

	components := []model.Component{
		{Name: "tool", Type: "binary", Locations: []string{"/usr/bin/tool"}},
		{Name: "app", Type: "npm", Locations: []string{"/srv/app/package.json"}},
		{Name: "nowhere", Type: "deb", Locations: []string{"/does/not/exist"}},
		{Name: "nolocation", Type: "deb"},
	}

	hashed, _ := HashComponents(context.Background(), root, 2, components)
	if hashed != 2 {
		t.Errorf("hashed = %d, want 2", hashed)
	}

	// Cross-check against an independently computed digest.
	sum := sha256.Sum256([]byte("tool contents"))
	want := hex.EncodeToString(sum[:])
	if components[0].SHA256 != want {
		t.Errorf("SHA256 = %q, want %q", components[0].SHA256, want)
	}
	if components[1].SHA256 == "" {
		t.Error("the npm component should have been hashed")
	}
	for _, i := range []int{2, 3} {
		if components[i].SHA256 != "" {
			t.Errorf("component %q has a digest but has no readable file", components[i].Name)
		}
	}
}

// TestHashComponentsSkipsSharedEvidenceFiles: several debs all cite
// /var/lib/dpkg/status. Digesting it would give every one of them the same
// hash and make all of them look changed whenever any package changed, which
// is the opposite of useful for change detection.
func TestHashComponentsSkipsSharedEvidenceFiles(t *testing.T) {
	root := t.TempDir()
	full := filepath.Join(root, "var/lib/dpkg/status")
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("Package: a\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	components := []model.Component{
		{Name: "a", Type: "deb", Locations: []string{"/var/lib/dpkg/status"}},
		{Name: "b", Type: "deb", Locations: []string{"/var/lib/dpkg/status"}},
		{Name: "c", Type: "deb", Locations: []string{"/var/lib/dpkg/status"}},
	}
	hashed, warnings := HashComponents(context.Background(), root, 1, components)
	if hashed != 0 {
		t.Errorf("hashed = %d, want 0: a file backing several components identifies none of them", hashed)
	}
	for _, c := range components {
		if c.SHA256 != "" {
			t.Errorf("%s got a digest from a shared package database", c.Name)
		}
	}
	if len(warnings) == 0 {
		t.Error("skipping shared evidence files should be announced")
	}
}

func TestHashComponentsIsDeterministic(t *testing.T) {
	root := t.TempDir()
	for i, name := range []string{"one", "two", "three"} {
		full := filepath.Join(root, "usr/bin", name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(strings.Repeat(name, i+1)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	build := func() []model.Component {
		return []model.Component{
			{Name: "one", Locations: []string{"/usr/bin/one"}},
			{Name: "two", Locations: []string{"/usr/bin/two"}},
			{Name: "three", Locations: []string{"/usr/bin/three"}},
		}
	}
	first := build()
	HashComponents(context.Background(), root, 4, first)
	for i := 0; i < 5; i++ {
		again := build()
		HashComponents(context.Background(), root, 4, again)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("hashing is not deterministic at iteration %d", i)
		}
	}
}

func TestHashComponentsEmpty(t *testing.T) {
	if n, _ := HashComponents(context.Background(), t.TempDir(), 0, nil); n != 0 {
		t.Errorf("hashed = %d, want 0", n)
	}
}

// --- nested root filesystems ------------------------------------------------

// TestDetectNestedRoots covers the most confusing thing swinv can do: walking
// into a second root filesystem stored inside this one - an extracted image, a
// container rootfs, a chroot, or this repository's own test fixture - and
// reporting its packages as installed, wearing the host's distribution label.
func TestDetectNestedRoots(t *testing.T) {
	components := []model.Component{
		// The real host database: must never be flagged.
		{Name: "bash", Type: "deb", Locations: []string{"/var/lib/dpkg/status"}},
		// A fixture tree carried in a source checkout.
		{Name: "openssl", Type: "deb", Locations: []string{"/opt/app/testdata/rootfs/var/lib/dpkg/status"}},
		// An extracted RPM-based image.
		{Name: "glibc", Type: "rpm", Locations: []string{"/srv/images/el9/var/lib/rpm"}},
		// Something with no database at all.
		{Name: "left-pad", Type: "npm", Locations: []string{"/srv/app/node_modules/left-pad/package.json"}},
	}

	warnings := DetectNestedRoots("/", components)
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly one", warnings)
	}
	w := warnings[0]
	for _, want := range []string{"/opt/app/testdata/rootfs", "/srv/images/el9", "--exclude"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning should mention %q; got: %s", want, w)
		}
	}
	if strings.Contains(w, "found 3 nested") {
		t.Errorf("the real root database was counted as nested: %s", w)
	}
}

// TestNestedRootPrefixCoversEveryPackageManager: the first implementation
// matched only the exact dpkg "status" path, so a nested RPM, apk, pacman or
// portage tree was invisible. Anchor on the database directory instead.
func TestNestedRootPrefixCoversEveryPackageManager(t *testing.T) {
	nested := []string{
		"/image/var/lib/dpkg/status",
		"/image/var/lib/dpkg/status.d/foo",
		"/image/var/lib/rpm",
		"/image/var/lib/rpm/Packages",
		"/image/var/lib/rpm/rpmdb.sqlite",
		"/image/usr/lib/sysimage/rpm/Packages.db",
		"/image/usr/share/rpm/Packages",
		"/image/lib/apk/db/installed",
		"/image/var/lib/pacman/local/bash-5.2/desc",
		"/image/var/db/pkg/app-shells/bash-5.2/CONTENTS",
	}
	for _, p := range nested {
		prefix, ok := nestedRootPrefix(p)
		if !ok {
			t.Errorf("%s was not recognised as a nested package database", p)
			continue
		}
		if prefix != "/image" {
			t.Errorf("%s -> prefix %q, want /image", p, prefix)
		}
	}

	// The scanned root's own databases must never be flagged.
	for _, p := range []string{
		"/var/lib/dpkg/status", "/var/lib/rpm", "/var/lib/rpm/Packages", "/lib/apk/db/installed",
		"/var/lib/pacman/local/bash-5.2/desc", "/var/db/pkg/app-shells/bash-5.2/CONTENTS",
	} {
		if _, ok := nestedRootPrefix(p); ok {
			t.Errorf("%s is the host's own database and must not be flagged", p)
		}
	}

	// Whole-segment matching: a lookalike path must not match.
	for _, p := range []string{"/srv/myvar/lib/rpmthing/x", "/opt/varlibdpkg/status"} {
		if _, ok := nestedRootPrefix(p); ok {
			t.Errorf("%s matched on a partial segment", p)
		}
	}
}

func TestDetectNestedRootsCleanHost(t *testing.T) {
	clean := []model.Component{
		{Name: "bash", Type: "deb", Locations: []string{"/var/lib/dpkg/status"}},
		{Name: "glibc", Type: "rpm", Locations: []string{"/var/lib/rpm"}},
		{Name: "musl", Type: "apk", Locations: []string{"/lib/apk/db/installed"}},
	}
	if got := DetectNestedRoots("/", clean); got != nil {
		t.Errorf("a host with only its own package databases must produce no warning, got %v", got)
	}
}

// TestDetectNestedRootsOnlyForRealRoot: scanning a fixture tree deliberately IS
// scanning a nested root, so warning about it would be noise.
func TestDetectNestedRootsOnlyForRealRoot(t *testing.T) {
	components := []model.Component{
		{Name: "openssl", Type: "deb", Locations: []string{"/opt/app/testdata/rootfs/var/lib/dpkg/status"}},
	}
	if got := DetectNestedRoots("/some/fixture", components); got != nil {
		t.Errorf("no warning expected for a non-root scan, got %v", got)
	}
}

// TestDropNestedRootComponents: --skip-nested-rootfs must remove only the
// components that exist *because of* a nested tree, never a real package that
// merely also appears in one.
func TestDropNestedRootComponents(t *testing.T) {
	roots := []string{"/opt/app/testdata/rootfs"}
	components := []model.Component{
		{Name: "bash", Type: "deb", Locations: []string{"/var/lib/dpkg/status"}},
		{Name: "phantom", Type: "deb", Locations: []string{"/opt/app/testdata/rootfs/var/lib/dpkg/status"}},
		// Read from the nested database, but Syft's file-ownership overlap also
		// attached a real host path. This is the case that made the naive
		// "every location is inside the tree" rule useless: it must still be
		// dropped, because its defining evidence is the nested database.
		{Name: "overlapped", Type: "deb", Locations: []string{
			"/opt/app/testdata/rootfs/var/lib/dpkg/status",
			"/usr/share/doc/libssl3/copyright",
		}},
		// A real host package that merely lives under a path resembling the
		// nested tree must survive: its evidence is the host's own database.
		{Name: "realpkg", Type: "deb", Locations: []string{"/var/lib/dpkg/status", "/opt/app/testdata/rootfs/usr/bin/thing"}},
		// Syft merged a genuinely installed package with a same-name entry from
		// the nested tree. It cites BOTH databases, so it must be kept: losing
		// real installed software is far worse than one package too many.
		{Name: "merged", Type: "deb", Locations: []string{
			"/var/lib/dpkg/status",
			"/opt/app/testdata/rootfs/var/lib/dpkg/status",
		}},
		{Name: "nolocation", Type: "deb"},
	}

	kept, dropped := DropNestedRootComponents(components, roots)
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2 (phantom and overlapped)", dropped)
	}
	names := map[string]bool{}
	for _, c := range kept {
		names[c.Name] = true
	}
	for _, gone := range []string{"phantom", "overlapped"} {
		if names[gone] {
			t.Errorf("%q came from a nested package database and should have been dropped", gone)
		}
	}
	for _, want := range []string{"bash", "realpkg", "merged", "nolocation"} {
		if !names[want] {
			t.Errorf("%q cites the host's own database and must be kept", want)
		}
	}

	// No detected roots means nothing is touched.
	same, n := DropNestedRootComponents(components, nil)
	if n != 0 || len(same) != len(components) {
		t.Errorf("with no nested roots nothing should change, got %d dropped", n)
	}
}

// TestParseMountinfoExcludesHostSharedFilesystems is the regression test for a
// bug found on a real Fedora 44 guest under WSL2. /usr/lib/wsl is a 9p mount
// carrying the *Windows host's* driver packages, and 9p was not in the
// non-local list - so 477 of that host's 1,003 components (48% of the whole
// inventory) were ASUS, Intel and NVIDIA binaries and .NET assemblies reported
// as installed Linux software, with nothing marking them foreign.
//
// The same shape applies to every hypervisor's shared-folder driver, which is
// why they are all listed rather than just the one that was caught.
func TestParseMountinfoExcludesHostSharedFilesystems(t *testing.T) {
	const table = `100 28 0:89 / /usr/lib/wsl/drivers ro,relatime - 9p drivers ro
101 28 0:90 / /usr/lib/wsl/lib ro,relatime - overlay overlay ro
102 28 0:91 / /media/host rw,relatime - virtiofs myfs rw
103 28 0:92 / /mnt/hgfs rw,relatime - vmhgfs .host:/ rw
104 28 0:93 / /media/sf_share rw,relatime - vboxsf share rw
105 28 0:94 / /media/psf rw,relatime - prl_fs share rw
106 28 0:95 / /mnt/win rw,relatime - drvfs C:\134 rw
107 28 0:96 / /srv/ceph rw,relatime - ceph 1.2.3.4:/ rw
108 28 0:97 / /srv/gluster rw,relatime - glusterfs gv0 rw
109 28 0:98 / /srv/bucket rw,relatime - fuse.s3fs s3fs rw
28 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
110 28 0:99 / /data rw,relatime - xfs /dev/sdb1 rw
`
	got := ParseMountinfo(strings.NewReader(table))

	for _, want := range []string{
		"/usr/lib/wsl/drivers", // 9p - the one that actually bit
		"/usr/lib/wsl/lib",     // overlay
		"/media/host",          // virtiofs
		"/mnt/hgfs",            // VMware
		"/media/sf_share",      // VirtualBox
		"/media/psf",           // Parallels
		"/mnt/win",             // WSL1 drvfs
		"/srv/ceph", "/srv/gluster", "/srv/bucket",
	} {
		if !contains(got, want) {
			t.Errorf("%q should have been excluded as a non-local filesystem; got %v", want, got)
		}
	}

	// Genuinely local storage must still be scanned, and / never excluded.
	for _, unwanted := range []string{"/", "/data"} {
		if contains(got, unwanted) {
			t.Errorf("%q is local storage and must not be excluded", unwanted)
		}
	}
}

// TestUnquoteDistroValues is the regression test for a bug found on Gentoo,
// whose /etc/os-release writes ID='gentoo' with single quotes. Syft's parser
// leaves them in the value, so host.os_id arrived as 'gentoo' - five extra
// characters in a CSV column and a fleet grouping key, making a query as
// ordinary as WHERE os_id = 'gentoo' match nothing.
func TestUnquoteDistroValues(t *testing.T) {
	cases := map[string]string{
		"'gentoo'":       "gentoo",
		`"debian"`:       "debian",
		"'Gentoo Linux'": "Gentoo Linux",
		"'2.18'":         "2.18",
		"fedora":         "fedora", // already clean
		"":               "",
		"'":              "'", // a lone quote is not a pair
		`"`:              `"`,
		"'mixed\"":       "'mixed\"", // mismatched, leave alone
	}
	for in, want := range cases {
		if got := unquote(in); got != want {
			t.Errorf("unquote(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLooksLikeRootFilesystem covers the signal used to decide whether the
// filesystem-layout exclusions apply to a --root other than "/".
func TestLooksLikeRootFilesystem(t *testing.T) {
	if !LooksLikeRootFilesystem("/") {
		t.Error(`"/" must always count as a root filesystem`)
	}

	// A mounted image or chroot: has etc/os-release.
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc/os-release"), []byte("ID=debian\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !LooksLikeRootFilesystem(rootfs) {
		t.Error("a tree with etc/os-release should be treated as a root filesystem")
	}

	// usr/lib/os-release alone is enough; some images ship only that.
	alt := t.TempDir()
	if err := os.MkdirAll(filepath.Join(alt, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(alt, "usr/lib/os-release"), []byte("ID=fedora\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !LooksLikeRootFilesystem(alt) {
		t.Error("usr/lib/os-release should also count")
	}

	// An ordinary directory must not be mistaken for one.
	plain := t.TempDir()
	if err := os.MkdirAll(filepath.Join(plain, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if LooksLikeRootFilesystem(plain) {
		t.Error("a directory with an empty etc/ is not a root filesystem")
	}
}

// TestMountedRootfsGetsLayoutExclusions is the regression test for a gap found
// by running the documented container command. Scanning the host from inside a
// container with "-v /:/host:ro --root /host" applied NO exclusions at all,
// because they were gated on the root being exactly "/". The scan then walked
// /host/proc, /host/sys and every home directory on the machine.
func TestMountedRootfsGetsLayoutExclusions(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc/os-release"), []byte("ID=ubuntu\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, warnings, err := BuildExcludes(ExcludeOptions{Root: rootfs})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"./proc/**", "./sys/**", "./home/**", "./root/**"} {
		if !contains(got, want) {
			t.Errorf("a mounted root filesystem should exclude %q; got %v", want, got)
		}
	}
	var announced bool
	for _, w := range warnings {
		if strings.Contains(w, "root filesystem") {
			announced = true
		}
	}
	if !announced {
		t.Error("applying layout exclusions to a non-/ root must be announced, not silent")
	}

	// An ordinary directory still gets nothing, which is the original contract.
	plain, _, err := BuildExcludes(ExcludeOptions{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 0 {
		t.Errorf("an arbitrary directory should get no layout exclusions, got %v", plain)
	}
}

// TestCleanVersionDropsPlaceholders pins a defect reported by a downstream
// vulnerability matcher. Syft emits "UNKNOWN" when a cataloger cannot
// determine a version, and that string is valid syntax in several version
// grammars: under Debian ordering it has no epoch, compares as epoch 0, and
// sorts below every real release. The matcher concluded "vulnerable" for every
// advisory ever filed against the package.
func TestCleanVersionDropsPlaceholders(t *testing.T) {
	for _, in := range []string{"UNKNOWN", "unknown", "Unknown", "  UNKNOWN  "} {
		if got := cleanVersion(in); got != "" {
			t.Errorf("cleanVersion(%q) = %q, want empty", in, got)
		}
	}

	// Real versions, including ones that merely contain the letters.
	for _, in := range []string{
		"1.2.3", "1:2.17.1-1ubuntu0.3", "3.0.11-1~deb12u2",
		"24.08", "unknown-1.0", "1.0-unknown",
	} {
		if got := cleanVersion(in); got != in {
			t.Errorf("cleanVersion(%q) = %q, want it unchanged", in, got)
		}
	}
}
