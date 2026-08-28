// Package elflink reads what a binary is dynamically linked against.
//
// Every ELF binary already carries a database of its own dependencies: the
// DT_NEEDED entries name the shared libraries it loads, and the dynamic symbol
// table names every function it imports from them, with versions. Nothing has
// to be executed to read either -- which is what makes this a scanner's job at
// all.
//
// The value is the join this enables. A package inventory says openssl is
// installed; this says sshd, listening on 0.0.0.0:22, loads libcrypto.so.3
// from that package and calls 120 of its functions. A CVE in a common library
// can then be ranked by which network-facing services actually load it,
// instead of flagging every machine that merely has it on disk.
//
// Two limits are inherent and stated rather than hidden. DT_NEEDED is
// link-time truth only: nginx's modules, Python's C extensions, PAM and NSS
// arrive by dlopen and are invisible here. And an imported symbol list names
// the API entry points the binary calls, not the code that runs -- most CVEs
// live in internal functions that never appear in any import table -- so
// "loads the library" is the reliable signal and the symbols are supporting
// evidence, never a verdict.
package elflink

import (
	"debug/elf"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Link is one shared library a binary loads.
type Link struct {
	// Soname is the name the binary asks for: "libcrypto.so.3".
	Soname string

	// Path is where the dynamic linker would find it, resolved the way ld.so
	// resolves it (RPATH/RUNPATH with $ORIGIN, then the configured and
	// standard directories) but without executing anything. Empty when the
	// library could not be found, which is itself worth reporting: the binary
	// says it needs something the filesystem does not provide.
	Path string

	// Direct is true for the binary's own DT_NEEDED entries, false for
	// libraries reached transitively -- postgres needs libpq, libpq needs
	// libssl. A consumer ranking "does this service load the vulnerable
	// library" usually wants both, but they are different strengths of
	// statement and are told apart.
	Direct bool

	// Symbols are the named functions and objects the *probed binary* imports
	// from this library, with versions where the ELF records them:
	// "RSA_set0_key@OPENSSL_3.0.0". Only filled for direct links when asked
	// for -- see Options.Symbols -- and capped; see Truncated.
	Symbols []string

	// NSymbols counts them even when the list itself was not requested, so
	// the cheap default still says how much of the library's surface is used.
	NSymbols int

	// Truncated is set when the symbol list hit the cap.
	Truncated bool
}

// Options controls a probe.
type Options struct {
	// Root is the filesystem the binary lives in: "/" for the host, or a
	// container's /proc/<pid>/root. Every path in the result is relative to
	// it, which is what lets the caller join against that filesystem's own
	// package database.
	Root string

	// Symbols asks for the imported symbol lists, not only their counts.
	Symbols bool

	// MaxDepth bounds the transitive walk. 0 means direct only; the default
	// used by Probe is enough to reach libssl through libpq without walking
	// the whole graph.
	MaxDepth int
}

// maxSymbols caps one binary's symbol list. systemd-resolved imports 679 and
// is among the largest seen; the cap exists for the pathological case, not the
// normal one, and hitting it is recorded rather than silent.
const maxSymbols = 5000

// defaultDepth reaches the common indirections (binary -> libpq -> libssl)
// without walking glibc's entire closure.
const defaultDepth = 3

// Probe reads what one binary links against.
//
// A binary with no dynamic section -- a static Go binary, most of this
// machine's own tooling -- returns an empty result and no error: it loads
// nothing, which is an answer, not a failure.
func Probe(exe string, opts Options) ([]Link, error) {
	if opts.Root == "" {
		opts.Root = "/"
	}
	if opts.MaxDepth == 0 {
		opts.MaxDepth = defaultDepth
	}

	real := filepath.Join(opts.Root, filepath.FromSlash(exe))
	f, err := elf.Open(real)
	if err != nil {
		return nil, fmt.Errorf("elflink: %w", err)
	}
	defer func() { _ = f.Close() }()

	needed, err := f.ImportedLibraries()
	if err != nil || len(needed) == 0 {
		// No dynamic section, or an empty one: statically linked.
		return nil, nil
	}

	// Which library each imported symbol comes from, for the per-link lists.
	// ImportedSymbols fails on stripped-of-versions binaries; the links are
	// still worth having without it.
	bySoname := map[string][]string{}
	if syms, err := f.ImportedSymbols(); err == nil {
		for _, s := range syms {
			name := s.Name
			if s.Version != "" {
				name += "@" + s.Version
			}
			bySoname[s.Library] = append(bySoname[s.Library], name)
		}
	}

	resolver := newResolver(opts.Root)
	searchpath := searchDirs(f, filepath.Dir(exe))

	var out []Link
	seen := map[string]bool{}
	type item struct {
		soname string
		dirs   []string
		depth  int
	}
	queue := make([]item, 0, len(needed))
	for _, so := range needed {
		queue = append(queue, item{so, searchpath, 1})
	}

	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if seen[it.soname] {
			continue
		}
		seen[it.soname] = true

		// A DT_NEEDED entry is a bare soname ("libcrypto.so.3"). A crafted
		// binary can put a path there ("../../../etc/shadow"); ld.so treats a
		// slash-bearing name as a path, and honouring that from an
		// attacker-controlled binary would have the root probe re-root and
		// stat arbitrary host files. A real soname never contains a slash, so
		// reject the ones that do rather than resolve them.
		if strings.ContainsRune(it.soname, '/') {
			out = append(out, Link{Soname: it.soname, Direct: it.depth == 1})
			continue
		}

		path := resolver.resolve(it.soname, it.dirs)
		link := Link{Soname: it.soname, Path: path, Direct: it.depth == 1}

		symbols := bySoname[it.soname]
		sort.Strings(symbols)
		link.NSymbols = len(symbols)
		if opts.Symbols && link.Direct {
			if len(symbols) > maxSymbols {
				symbols = symbols[:maxSymbols]
				link.Truncated = true
			}
			link.Symbols = symbols
		}
		out = append(out, link)

		// The library's own needs, bounded. Its RUNPATH applies to what it
		// loads, exactly as ld.so would.
		if path != "" && it.depth < opts.MaxDepth {
			if lf, err := elf.Open(filepath.Join(opts.Root, filepath.FromSlash(path))); err == nil {
				if subNeeded, err := lf.ImportedLibraries(); err == nil {
					subDirs := searchDirs(lf, filepath.Dir(path))
					for _, so := range subNeeded {
						if !seen[so] {
							queue = append(queue, item{so, subDirs, it.depth + 1})
						}
					}
				}
				_ = lf.Close()
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Direct != out[j].Direct {
			return out[i].Direct
		}
		return out[i].Soname < out[j].Soname
	})
	return out, nil
}

// searchDirs builds the per-object search list: DT_RUNPATH (or DT_RPATH when
// no RUNPATH is set, matching ld.so's precedence), with $ORIGIN expanded to
// the directory holding the object. LD_LIBRARY_PATH is deliberately not
// honoured: the scanner's environment is not the daemon's, and resolving
// through it would describe the scan rather than the service.
func searchDirs(f *elf.File, origin string) []string {
	runpath, _ := f.DynString(elf.DT_RUNPATH)
	if len(runpath) == 0 {
		runpath, _ = f.DynString(elf.DT_RPATH)
	}
	var out []string
	for _, entry := range runpath {
		for _, dir := range strings.Split(entry, ":") {
			if dir == "" {
				continue
			}
			dir = strings.ReplaceAll(dir, "$ORIGIN", origin)
			dir = strings.ReplaceAll(dir, "${ORIGIN}", origin)
			out = append(out, dir)
		}
	}
	return out
}

// resolver finds sonames the way the dynamic linker would, against a chosen
// filesystem root.
type resolver struct {
	root string
	dirs []string
	// cache spares repeated stats when many binaries share libraries.
	cache map[string]string
}

// standardDirs mirrors ld.so's built-in defaults plus the multiarch layout.
var standardDirs = []string{
	"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
	"/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
	"/lib64", "/usr/lib64",
	"/lib", "/usr/lib",
	"/usr/local/lib",
}

func newResolver(root string) *resolver {
	r := &resolver{root: root, cache: map[string]string{}}
	r.dirs = append(r.dirs, ldConfDirs(root)...)
	r.dirs = append(r.dirs, standardDirs...)
	return r
}

// resolve returns the path a soname lands on, object search dirs first.
func (r *resolver) resolve(soname string, objectDirs []string) string {
	// A soname containing a slash is used as a path, not searched for.
	if strings.Contains(soname, "/") {
		return r.realpath(soname)
	}
	if hit, ok := r.cache[soname]; ok && len(objectDirs) == 0 {
		return hit
	}
	for _, dir := range append(append([]string{}, objectDirs...), r.dirs...) {
		if real := r.realpath(dir + "/" + soname); real != "" {
			if len(objectDirs) == 0 {
				r.cache[soname] = real
			}
			return real
		}
	}
	if len(objectDirs) == 0 {
		r.cache[soname] = ""
	}
	return ""
}

// realpath chases symlinks manually, re-rooting every absolute target under
// the probe root.
//
// This is not pedantry. The soname path a binary loads -- libz.so.1 -- is
// usually a symlink ldconfig created, which no package ships: dpkg owns
// libz.so.1.3.1, the target, so probing the symlink's path finds no owner and
// the library reports as unmanaged when it is anything but. And the chase has
// to happen under the root by hand, because for a container probed through
// /proc/<pid>/root an absolute symlink target resolved by the OS would walk
// straight out of the container and onto the host's copy of the library.
func (r *resolver) realpath(p string) string {
	const maxHops = 8
	for hop := 0; hop < maxHops; hop++ {
		full := filepath.Join(r.root, filepath.FromSlash(p))
		fi, err := os.Lstat(full)
		if err != nil {
			return ""
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			if fi.Mode().IsRegular() {
				// Cleaned, so a crafted DT_NEEDED like "../../../etc/shadow"
				// cannot make the caller record or re-open an un-normalised
				// path that names a file outside the intended library search.
				// filepath.Join above already jails the read under r.root;
				// this makes the returned string honest too.
				return path.Clean(p)
			}
			return ""
		}
		target, err := os.Readlink(full)
		if err != nil {
			return ""
		}
		if strings.HasPrefix(target, "/") {
			p = path.Clean(target)
		} else {
			p = path.Join(path.Dir(p), target)
		}
	}
	return ""
}

// ldConfDirs reads the directories /etc/ld.so.conf configures, following one
// level of include globs, which is how every distribution actually writes it.
// Best-effort throughout: a container with no ld.so.conf just gets the
// standard directories.
func ldConfDirs(root string) []string {
	var out []string
	seen := map[string]bool{}

	var readConf func(string, int)
	readConf = func(name string, depth int) {
		if depth > 2 {
			return
		}
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil || len(raw) > 1<<20 {
			return
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			switch {
			case line == "" || strings.HasPrefix(line, "#"):
			case strings.HasPrefix(line, "include "):
				pattern := strings.TrimSpace(strings.TrimPrefix(line, "include "))
				matches, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
				sort.Strings(matches)
				for _, m := range matches {
					rel, err := filepath.Rel(root, m)
					if err == nil {
						readConf("/"+filepath.ToSlash(rel), depth+1)
					}
				}
			case strings.HasPrefix(line, "/"):
				if !seen[line] {
					seen[line] = true
					out = append(out, line)
				}
			}
		}
	}
	readConf("/etc/ld.so.conf", 0)
	return out
}

// Paths returns every resolved library path in a set of links, for handing to
// an ownership probe.
func Paths(links []Link) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range links {
		if l.Path != "" && !seen[l.Path] {
			seen[l.Path] = true
			out = append(out, l.Path)
		}
	}
	sort.Strings(out)
	return out
}
