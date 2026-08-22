package pathnorm

import (
	"os"
	"path/filepath"
	"testing"
)

// The two sides disagree about the same file on every merged-/usr system:
// dpkg on Ubuntu 24.04 says netcat-openbsd owns /bin/nc.openbsd, while
// /proc/<pid>/exe reports /usr/bin/nc.openbsd. A plain comparison misses, and
// the running nc is reported as software no package manager installed.
func TestUsrMergeFoldsPreMergePaths(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"usr/bin", "usr/lib"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"bin", "lib"} {
		if err := os.Symlink("usr/"+d, filepath.Join(root, d)); err != nil {
			t.Fatal(err)
		}
	}
	// A real directory, as on Alpine: nothing to fold.
	if err := os.MkdirAll(filepath.Join(root, "sbin"), 0o755); err != nil {
		t.Fatal(err)
	}

	canon := UsrMerge(root)
	cases := map[string]string{
		"/bin/nc.openbsd":      "/usr/bin/nc.openbsd",
		"/usr/bin/nc.openbsd":  "/usr/bin/nc.openbsd",
		"/lib/systemd/systemd": "/usr/lib/systemd/systemd",
		"/sbin/chronyd":        "/sbin/chronyd",
		"/opt/vendor/app":      "/opt/vendor/app",
		"/bin":                 "/bin",
		"relative":             "relative",
	}
	for in, want := range cases {
		if got := canon(in); got != want {
			t.Errorf("canon(%q) = %q, want %q", in, got, want)
		}
	}

}

// On a system with no merge -- Alpine, or an old tree -- /bin/busybox and
// /usr/bin/busybox are different files, and folding them would invent a match.
func TestUsrMergeIsAStatNotAnAssumption(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"bin", "sbin", "lib", "usr/bin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	canon := UsrMerge(root)
	if got := canon("/bin/busybox"); got != "/bin/busybox" {
		t.Errorf("canon(/bin/busybox) = %q on an unmerged tree", got)
	}
}
