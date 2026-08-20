package scan

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// defaultExcludeDirs are the directory trees skipped for a scan rooted at "/".
// They are either kernel-synthetic (proc, sys, dev), volatile (run, tmp),
// caches that hold no installed software (var/cache), or container image
// stores whose contents belong to a different machine image rather than to
// this host (var/lib/docker and friends). Paths are relative to the scan root
// and MUST NOT carry a leading slash: the pattern form is built by dirPattern.
var defaultExcludeDirs = []string{
	"proc",
	"sys",
	"dev",
	"run",
	"tmp",
	"var/tmp",
	"var/cache",
	"var/lib/docker",
	"var/lib/containers",
	"var/lib/containerd",
	"var/lib/kubelet/pods",
	"mnt",
	"media",
	"lost+found",
	// Volatile state that holds no installed software but can be very large.
	"var/log",
	"var/spool",
	"var/crash",
	"var/backups",
	"var/lib/systemd/coredump",
}

// homeExcludeDirs are the user home trees, skipped unless IncludeHome is set.
//
// They are excluded by default because they dominate everything else: on the
// development host /home alone held 508,687 files and 40 GB across 86
// node_modules trees — more than the rest of the filesystem combined. With them
// excluded a full scan of that host takes ~5 minutes; with them included it does
// not finish in a comparable time. They are also per-user, high-churn, and
// privacy-sensitive, none of which is true of the machine's own software.
// A workstation inventory that genuinely wants them can pass --include-home.
// See docs/PERFORMANCE.md for the measured figures.
var homeExcludeDirs = []string{
	"home",
	"root",
}

// noiseExcludePatterns are matched at any depth. They are build and VCS
// artefacts that are never installed software but are numerous and deep.
var noiseExcludePatterns = []string{
	"**/.git/**",
	"**/__pycache__/**",
	"**/.cache/**",
}

// defaultExcludeFiles are single files skipped for a scan rooted at "/". They
// are large, opaque, and never contain installed software, but a classifier
// will happily read every byte of them.
var defaultExcludeFiles = []string{
	"swapfile",
	"swap.img",
}

// snapExcludeDir and flatpakExcludeDir are the trees suppressed by the
// --no-snap and --no-flatpak options. Both hold genuinely installed software,
// which is why they are included by default, but both also vendor entire
// runtimes and can dominate scan time and component count.
const (
	snapExcludeDir    = "snap"
	flatpakExcludeDir = "var/lib/flatpak"
)

// nonLocalFilesystems are the mountinfo filesystem types that must not be
// walked. Three groups, all of which describe storage that is not part of this
// machine's own installation:
//
//   - Network filesystems, which would turn a local scan into a remote one.
//   - Host-shared filesystems, where a hypervisor or WSL projects the *host's*
//     directories into this guest. Software found there belongs to another
//     operating system entirely.
//   - Virtual and in-memory filesystems, which hold no installed software.
//
// The host-shared group is the one that bites hardest, because the software it
// exposes looks completely genuine. On a Fedora guest under WSL2, /usr/lib/wsl
// is a 9p mount carrying the Windows host's drivers; before 9p was listed here
// it contributed 477 of 1,003 components — 48% of the inventory — as ASUS,
// Intel and NVIDIA binaries and .NET assemblies reported as installed Linux
// software. Nothing in the report marked them as foreign.
//
// Skipping these is also the single biggest determinant of whether a full-root
// scan takes seconds or hours.
var nonLocalFilesystems = map[string]struct{}{
	// Network filesystems.
	"nfs":           {},
	"nfs4":          {},
	"cifs":          {},
	"smbfs":         {},
	"smb3":          {},
	"ceph":          {},
	"glusterfs":     {},
	"lustre":        {},
	"beegfs":        {},
	"afs":           {},
	"sshfs":         {},
	"fuse.sshfs":    {},
	"fuse.rclone":   {},
	"fuse.s3fs":     {},
	"fuse.gcsfuse":  {},
	"fuse.blobfuse": {},

	// Host-shared: a hypervisor or WSL projecting the host's files into a
	// guest. 9p is WSL2 and QEMU/KVM virtfs; virtiofs is the modern
	// replacement; drvfs and lxfs are WSL1; the rest are the desktop
	// hypervisors' shared-folder drivers.
	"9p":            {},
	"virtiofs":      {},
	"fuse.virtiofs": {},
	"drvfs":         {},
	"lxfs":          {},
	"vboxsf":        {},
	"vmhgfs":        {},
	"fuse.vmhgfs":   {},
	"prl_fs":        {},

	// Automounters, which the walk itself would otherwise trigger.
	"autofs": {},

	// Virtual, in-memory and image filesystems.
	"overlay":  {},
	"squashfs": {},
	"tmpfs":    {},
	"devtmpfs": {},
	"proc":     {},
	"sysfs":    {},
	"cgroup":   {},
	"cgroup2":  {},
}

// maxListedMounts caps how many mount points a single warning enumerates. A
// systemd host can easily have thirty tmpfs mounts and the warning list is
// meant to be read by a human.
const maxListedMounts = 10

// ExcludeOptions describes how the final exclusion pattern list is assembled.
// The zero value is valid but excludes nothing beyond the filesystem-layout
// defaults; callers normally set AutoExcludeMounts.
type ExcludeOptions struct {
	// Root is the filesystem root the scan will run against, normally "/".
	// The filesystem-layout defaults are only applied when Root is "/", and
	// mount points are recorded relative to Root.
	Root string

	// UserExcludes are patterns supplied by the operator (repeatable
	// --exclude). They are validated exactly like generated patterns.
	UserExcludes []string

	// AutoExcludeMounts enables reading the mount table and excluding every
	// non-local filesystem found there. Default true at the CLI layer.
	AutoExcludeMounts bool

	// NoSnap excludes the snap tree.
	NoSnap bool

	// NoFlatpak excludes the flatpak tree.
	NoFlatpak bool

	// IncludeHome scans the user home trees (/home and /root). Off by default:
	// see homeExcludeDirs for why.
	IncludeHome bool

	// MountinfoPath overrides the mount table location. Empty means
	// /proc/self/mountinfo; tests point it at a fixture.
	MountinfoPath string
}

// BuildExcludes assembles the final exclusion list from the filesystem-layout
// defaults, the non-local mount points found in the mount table, the optional
// snap and flatpak trees, and the operator's own patterns. The result is
// validated, deduplicated, and sorted, so two runs on an unchanged machine
// produce an identical ScanMeta.Excluded list.
//
// The returned warnings explain what was excluded automatically and why; they
// are meant to be recorded in ScanMeta.Warnings. An error is returned only for
// a pattern Syft would reject, and names the offending pattern so the caller
// can exit with a usage error.
func BuildExcludes(o ExcludeOptions) (patterns []string, warnings []string, err error) {
	root := normalizeRoot(o.Root)

	patterns = append(patterns, DefaultExcludes(root)...)

	// Say so when the layout defaults were applied to something other than "/",
	// because it is a real behaviour change for that scan and the operator
	// should not have to infer it from the excluded list.
	if root != "/" && LooksLikeRootFilesystem(root) {
		warnings = append(warnings, fmt.Sprintf(
			"%s looks like a root filesystem (it has etc/os-release), so the usual layout "+
				"exclusions were applied; pass --no-auto-exclude-mounts and your own --exclude "+
				"patterns if you want the whole tree walked", root))
	}

	if !o.IncludeHome {
		if home := HomeExcludes(root); len(home) > 0 {
			patterns = append(patterns, home...)
			warnings = append(warnings,
				"user home directories (/home, /root) were not scanned; pass --include-home to include them")
		}
	}

	if o.AutoExcludeMounts {
		mountPatterns, excluded, mountWarnings := mountExcludes(root, o.MountinfoPath, o.NoSnap)
		patterns = append(patterns, mountPatterns...)
		warnings = append(warnings, mountWarnings...)
		if len(excluded) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"auto-excluded %d non-local filesystem mount point(s): %s",
				len(excluded), summarizeList(excluded)))
		}
	}

	if o.NoSnap {
		patterns = append(patterns, dirPattern(snapExcludeDir))
		warnings = append(warnings, "excluded /snap on request: snap packages will be missing from the inventory")
	}
	if o.NoFlatpak {
		patterns = append(patterns, dirPattern(flatpakExcludeDir))
		warnings = append(warnings, "excluded /var/lib/flatpak on request: flatpak packages will be missing from the inventory")
	}

	for _, p := range o.UserExcludes {
		patterns = append(patterns, strings.TrimSpace(p))
	}

	for _, p := range patterns {
		if err := ValidatePattern(p); err != nil {
			return nil, warnings, err
		}
	}

	return model.SortedSet(patterns), warnings, nil
}

// LooksLikeRootFilesystem reports whether a directory is the root of a Linux
// installation rather than an arbitrary folder.
//
// The presence of etc/os-release is the signal. It is what every distribution
// writes at the top of its filesystem, it is what Syft itself keys distro
// detection on, and no ordinary directory has one.
//
// This matters because --root is documented for exactly this case: scanning a
// mounted image, a chroot, or the host from inside a container with
// "-v /:/host:ro --root /host". Without it, none of the layout exclusions
// applied to such a scan, so swinv would walk /host/proc, /host/sys and every
// home directory on the machine. That is not a hypothetical — it is what
// happened the first time the documented container command was run.
func LooksLikeRootFilesystem(root string) bool {
	root = normalizeRoot(root)
	if root == "/" {
		return true
	}
	for _, marker := range []string{"etc/os-release", "usr/lib/os-release"} {
		if fi, err := os.Stat(filepath.Join(filepath.FromSlash(root), filepath.FromSlash(marker))); err == nil && fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// DefaultExcludes returns the filesystem-layout exclusions for the given scan
// root. They describe the layout of a running Linux system, so they apply to
// "/" and to any other tree that is itself a root filesystem — a mounted
// image, a chroot, the host bind-mounted into a container. An arbitrary
// directory has no such layout to assume, and gets nothing.
func DefaultExcludes(root string) []string {
	if !LooksLikeRootFilesystem(root) {
		return nil
	}
	out := make([]string, 0, len(defaultExcludeDirs)+len(defaultExcludeFiles)+len(noiseExcludePatterns))
	for _, dir := range defaultExcludeDirs {
		out = append(out, dirPattern(dir))
	}
	for _, f := range defaultExcludeFiles {
		out = append(out, filePattern(f))
	}
	out = append(out, noiseExcludePatterns...)
	return out
}

// HomeExcludes returns the user home trees for the given scan root, or nil
// when the root is not "/". Callers skip it when the operator asked for
// --include-home.
func HomeExcludes(root string) []string {
	if !LooksLikeRootFilesystem(root) {
		return nil
	}
	out := make([]string, 0, len(homeExcludeDirs))
	for _, dir := range homeExcludeDirs {
		out = append(out, dirPattern(dir))
	}
	return out
}

// ValidatePattern enforces the rule Syft's directory source applies to
// exclusion patterns: they are matched relative to the scan root, so they must
// begin with "./", "*/", or "**/". An absolute pattern such as "/var/cache/**"
// silently matches nothing, and anything else is rejected outright at source
// construction, so both are caught here where the message can teach the rule.
func ValidatePattern(p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("invalid exclusion pattern: pattern is empty (expected something like %q)", "./var/cache/**")
	}
	for _, prefix := range []string{"./", "*/", "**/"} {
		if strings.HasPrefix(p, prefix) {
			return nil
		}
	}
	return fmt.Errorf(
		"invalid exclusion pattern %q: exclusion patterns are relative to the scan root and must start with %q, %q, or %q "+
			"(for example %q to skip a directory tree, or %q to skip a file anywhere)",
		p, "./", "*/", "**/", "./var/cache/**", "**/*.iso")
}

// ParseMountinfo reads /proc/self/mountinfo and returns the mount points whose
// filesystem type is not local, in the order they appear and without
// duplicates. The root mount ("/") is never returned: excluding it would
// exclude the entire scan.
//
// The mountinfo format is
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime shared:1 - ext3 /dev/root rw
//
// where fields are space separated, the mount point is field 5, and a variable
// number of optional "tag:value" fields ends at a lone "-" separator followed
// by the filesystem type. Path fields are octal-escaped by the kernel, so a
// mount point containing a space arrives as "/mnt/my\040disk". Lines that do
// not fit that shape are skipped rather than reported: an unparsable mount
// table entry must never fail a scan.
func ParseMountinfo(r io.Reader) []string {
	if r == nil {
		return nil
	}

	var out []string
	seen := make(map[string]struct{})

	sc := bufio.NewScanner(r)
	// Mount tables are short but a single line can be long on a host with many
	// bind mounts; bufio's 64KiB default is raised so one long line cannot
	// silently truncate the rest of the table.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		mountPoint, fsType, ok := parseMountinfoLine(sc.Text())
		if !ok {
			continue
		}
		if _, nonLocal := nonLocalFilesystems[fsType]; !nonLocal {
			continue
		}
		if mountPoint == "/" {
			continue
		}
		if _, dup := seen[mountPoint]; dup {
			continue
		}
		seen[mountPoint] = struct{}{}
		out = append(out, mountPoint)
	}

	return out
}

// parseMountinfoLine extracts the mount point and filesystem type from one
// mountinfo line. ok is false for any line that does not have the six
// mandatory fields, the "-" separator, and a filesystem type after it.
func parseMountinfoLine(line string) (mountPoint, fsType string, ok bool) {
	fields := strings.Fields(line)
	// 6 mandatory fields, the separator, and at least the filesystem type.
	if len(fields) < 8 {
		return "", "", false
	}

	// The separator is the first lone "-" at or after the optional-fields
	// section, which starts at index 6 (0-indexed).
	sep := -1
	for i := 6; i < len(fields); i++ {
		if fields[i] == "-" {
			sep = i
			break
		}
	}
	if sep < 0 || sep+1 >= len(fields) {
		return "", "", false
	}

	mountPoint = unescapeOctal(fields[4])
	if mountPoint == "" || !strings.HasPrefix(mountPoint, "/") {
		return "", "", false
	}

	return path.Clean(mountPoint), fields[sep+1], true
}

// unescapeOctal decodes the kernel's mountinfo path escaping, in which a
// backslash followed by three octal digits stands for one byte: \040 space,
// \011 tab, \012 newline, \134 backslash. Any other backslash sequence is left
// alone, since the kernel does not produce one.
func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 4
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// mountExcludes reads the mount table and turns every non-local mount point
// into an exclusion pattern relative to root. Mount points outside root are
// skipped: their absolute paths are meaningless inside another tree, and
// translating them blindly would exclude an unrelated directory.
//
// A mount table that cannot be read is a warning, never an error: the scan is
// still correct, only slower.
func mountExcludes(root, mountinfoPath string, noSnap bool) (patterns, excluded, warnings []string) {
	if mountinfoPath == "" {
		if defaultMountinfoPath == "" {
			// This platform keeps no mount table swinv can read. Reporting a
			// missing /proc path here would be technically true and useless:
			// it names a Linux file and gives Linux advice to someone who can
			// act on neither.
			return nil, nil, []string{noMountTableWarning}
		}
		mountinfoPath = defaultMountinfoPath
	}

	f, err := os.Open(mountinfoPath)
	if err != nil {
		return nil, nil, []string{fmt.Sprintf(
			"could not read %s (%v): non-local filesystems will not be auto-excluded and the scan may be slow",
			mountinfoPath, err)}
	}
	defer func() { _ = f.Close() }()

	for _, mountPoint := range ParseMountinfo(f) {
		// Snaps are squashfs loop mounts, so the non-local filesystem rule
		// would silently exclude every snap — defeating the deliberate
		// decision to treat snaps as installed software and making --no-snap
		// a no-op. Carve them out unless the operator actually asked for
		// --no-snap, which adds ./snap/** through the normal path.
		if !noSnap && isSnapMount(mountPoint) {
			continue
		}
		rel, ok := rootRelative(root, mountPoint)
		if !ok {
			continue
		}
		patterns = append(patterns, dirPattern(rel))
		excluded = append(excluded, mountPoint)
	}
	return patterns, excluded, nil
}

// snapMountRoots are the directories under which snapd mounts snap squashfs
// images. Anything else mounted squashfs (an ISO, an appliance image) is not
// installed software and stays excluded.
var snapMountRoots = []string{"/snap/", "/var/lib/snapd/snap/"}

// isSnapMount reports whether a mount point is a snap package mount.
func isSnapMount(mountPoint string) bool {
	for _, prefix := range snapMountRoots {
		if strings.HasPrefix(mountPoint+"/", prefix) {
			return true
		}
	}
	return false
}

// rootRelative converts an absolute system path into a path relative to the
// scan root. It reports false when the path is the root itself or lies outside
// it, in which case no pattern should be generated.
func rootRelative(root, abs string) (string, bool) {
	root = normalizeRoot(root)
	abs = path.Clean(abs)
	if root == "/" {
		rel := strings.TrimPrefix(abs, "/")
		return rel, rel != ""
	}
	if abs == root {
		return "", false
	}
	if !strings.HasPrefix(abs, root+"/") {
		return "", false
	}
	return abs[len(root)+1:], true
}

// normalizeRoot cleans a scan root into a slash-separated absolute path. An
// empty root means "/".
func normalizeRoot(root string) string {
	root = strings.TrimSpace(root)
	if root == "" {
		return "/"
	}
	return path.Clean(filepath.ToSlash(root))
}

// dirPattern renders a root-relative directory as the "./dir/**" exclusion
// form, which is what Syft matches a whole tree with.
func dirPattern(rel string) string {
	return "./" + strings.Trim(rel, "/") + "/**"
}

// filePattern renders a root-relative single file as the "./file" exclusion
// form.
func filePattern(rel string) string {
	return "./" + strings.Trim(rel, "/")
}

// summarizeList renders a human-readable, length-capped list for a warning.
func summarizeList(items []string) string {
	if len(items) <= maxListedMounts {
		return strings.Join(items, ", ")
	}
	shown := append([]string(nil), items[:maxListedMounts]...)
	return fmt.Sprintf("%s and %d more", strings.Join(shown, ", "), len(items)-maxListedMounts)
}
