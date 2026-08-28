// Package pelink reads what a Windows binary loads: the DLLs named in its PE
// import table, and the functions it imports from each, without executing
// anything.
//
// This is the Windows sibling of internal/elflink, and it exists for the same
// sentence: "a CVE landed in this library" is answered better by "these
// network-facing binaries actually load it" than by "it is on disk
// somewhere". The import table is load-time truth only - LoadLibrary calls
// and delay-loaded imports are the Windows dlopen, invisible here and said
// so in the evidence.
package pelink

import (
	"context"
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Link is one DLL a binary loads.
type Link struct {
	// Name is the DLL as the import table spells it, e.g. WS2_32.dll.
	Name string

	// Path is where the loader would find it, resolved application directory
	// first, then the system directory - the order Windows itself uses for
	// anything not already loaded. Empty for API set names (api-ms-win-*),
	// which are virtual and satisfied by the OS, and for DLLs found in
	// neither place, which at load time would mean a missing dependency and
	// at inventory time usually means a PATH or SxS resolution this probe
	// does not attempt.
	Path string

	// Direct marks a first-hop import; the rest arrived transitively.
	Direct bool

	NSymbols int
	Symbols  []string
	// SymbolsTruncated notes that the list was cut at maxSymbols.
	SymbolsTruncated bool
}

// Options configures a probe.
type Options struct {
	// Symbols keeps the imported function names, not only their count.
	Symbols bool

	// MaxDepth bounds the transitive walk. 0 means defaultDepth.
	MaxDepth int

	// SystemDir overrides where system DLLs are looked for. Empty means
	// %SystemRoot%\System32, or SysWOW64 for a 32-bit binary on a 64-bit
	// OS. Tests set it; nothing else should need to.
	SystemDir string

	// Polite paces the probe: after each file, each worker pauses as long
	// as the parse took (bounded), giving everything else half the wall
	// clock. The process being in background priority is not enough,
	// because the probe's cost is not its own CPU: every open is scanned by
	// the antivirus at ITS priority, so a probe that opens files as fast as
	// it can turns the AV into a foreground workload on 100k files.
	// Measured consequence before this existed: "almost killing the
	// computer it is running on". --fast turns it off.
	Polite bool

	// Logf receives progress, so a probe measured in minutes is visibly
	// alive rather than indistinguishable from a hang. May be nil.
	Logf func(string, ...any)
}

const (
	// maxSymbols caps one module's recorded import list, same bound as the
	// ELF probe: enough for evidence, not enough to bloat a report.
	maxSymbols = 5000

	// defaultDepth: direct imports, theirs, and one more hop. The same
	// shape as the ELF probe; system DLL graphs are deep and repetitive,
	// and three hops names every library that matters for the CVE join.
	defaultDepth = 3
)

// module is one binary's direct imports, grouped per DLL.
type module struct {
	name      string
	symbols   []string
	truncated bool
}

// Probe reads exe's import table and resolves each DLL the way the loader
// would, application directory first. A file that is not a PE binary returns
// (nil, nil): the caller probes everything that listens, and a script with a
// port open is not an error.
func Probe(exe string, opts Options) ([]Link, error) {
	return newProber().probe(exe, opts)
}

// prober carries a parse cache across binaries. The machine's executables
// overwhelmingly import the same system DLLs, and probing them all without
// a cache would re-open kernel32.dll once per binary on the machine.
type prober struct {
	mu    sync.Mutex
	cache map[string]parsed

	// polite paces every actual parse: the pacing lives here rather than
	// in the phase-A worker loop, because transitive system DLLs are
	// first-parsed by the sequential assembly phase - and a politeness
	// contract with a side door is not a contract.
	polite bool

	// ctx, when set, stops NEW parses after the deadline without stopping
	// cache reads: thirty minutes of completed parsing must not be thrown
	// away because the thirty-first would be too many. A real run probed
	// 42,411 of 46,325 files and then reported zero, because the assembly
	// loop obeyed the same expired context as the work it was assembling.
	ctx context.Context

	// statCache remembers whether a resolution candidate exists, keyed by
	// lowered path. Every binary's BFS re-resolves the same system DLLs -
	// ntdll, KERNELBASE, msvcrt - and 46,000 binaries times up to three
	// stats per import was millions of serial syscalls through the
	// filesystem filter drivers, in a loop whose comment claimed it was
	// pure map lookups. Negative answers are cached too; they repeat just
	// as often.
	statCache map[string]bool

	// firstErr keeps the first parse failure verbatim. When a whole machine
	// produces zero links, the difference between "every open failed with
	// ERROR_ACCESS_DENIED" and "these are not PE files" is the entire
	// diagnosis, and a probe that swallows it forces a guessing game.
	firstErr error
}

type parsed struct {
	mods    []module
	machine uint16
	notPE   bool
}

func newProber() *prober {
	return &prober{cache: map[string]parsed{}, statCache: map[string]bool{}}
}

// imports parses one file through the cache. Keyed case-insensitively,
// because NTFS is.
func (p *prober) imports(path string) ([]module, uint16, bool) {
	key := strings.ToLower(path)
	p.mu.Lock()
	entry, ok := p.cache[key]
	p.mu.Unlock()
	if !ok {
		if p.ctx != nil && p.ctx.Err() != nil {
			// Past the deadline: answer from the cache only. Not cached as
			// not-PE, because that would be recording a fact nobody checked.
			return nil, 0, false
		}
		start := time.Now()
		mods, machine, err := parseImports(path)
		if p.polite {
			ctx := p.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			pause(ctx, politePause(time.Since(start)))
		}
		entry = parsed{mods: mods, machine: machine, notPE: err != nil}
		p.mu.Lock()
		if err != nil && p.firstErr == nil {
			p.firstErr = fmt.Errorf("%s: %w", path, err)
		}
		p.cache[key] = entry
		p.mu.Unlock()
	}
	return entry.mods, entry.machine, !entry.notPE
}

func (p *prober) probe(exe string, opts Options) ([]Link, error) {
	depth := opts.MaxDepth
	if depth <= 0 {
		depth = defaultDepth
	}

	direct, machine, ok := p.imports(exe)
	if !ok {
		return nil, nil // not a PE binary
	}
	if len(direct) == 0 {
		return nil, nil
	}

	sysDir := opts.SystemDir
	if sysDir == "" {
		sysDir = systemDir(machine)
	}
	appDir := filepath.Dir(exe)

	var out []Link
	seen := map[string]bool{}

	type item struct {
		mod  module
		from string // directory of the importing object
		hop  int
	}
	queue := make([]item, 0, len(direct))
	for _, m := range direct {
		queue = append(queue, item{mod: m, from: appDir, hop: 1})
	}

	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		key := strings.ToLower(it.mod.name)
		if seen[key] {
			continue
		}
		seen[key] = true

		l := Link{
			Name:     it.mod.name,
			Direct:   it.hop == 1,
			NSymbols: len(it.mod.symbols),
		}
		// Direct links only, matching the ELF probe and the model's own
		// documentation. A transitive symbol list describes what one system
		// DLL asks of another - no consumer ranks on that, and keeping it
		// for every KERNELBASE import on the machine is what turned the
		// symbol option into a garbage-collector workout.
		if opts.Symbols && l.Direct {
			l.Symbols = it.mod.symbols
			l.SymbolsTruncated = it.mod.truncated
		}

		if !isAPISet(it.mod.name) {
			l.Path = p.resolve(it.mod.name, it.from, appDir, sysDir)
		}
		out = append(out, l)

		if l.Path == "" || it.hop >= depth {
			continue
		}
		next, _, peOK := p.imports(l.Path)
		if !peOK {
			continue // resolved to something that is not a PE binary; record, do not descend
		}
		for _, m := range next {
			queue = append(queue, item{mod: m, from: filepath.Dir(l.Path), hop: it.hop + 1})
		}
	}
	return out, nil
}

// parseImports reads one PE file's import table, grouped per DLL in table
// order.
//
// debug/pe surfaces the imports as "Symbol:DLL.dll" strings; the grouping
// preserves the DLL order the binary declared.
func parseImports(path string) ([]module, uint16, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()

	syms, err := f.ImportedSymbols()
	if err != nil {
		return nil, f.Machine, fmt.Errorf("pelink: reading imports of %s: %w", path, err)
	}

	index := map[string]int{}
	var mods []module
	for _, s := range syms {
		name, dll, ok := strings.Cut(s, ":")
		if !ok || dll == "" {
			continue
		}
		i, exists := index[strings.ToLower(dll)]
		if !exists {
			i = len(mods)
			index[strings.ToLower(dll)] = i
			mods = append(mods, module{name: dll})
		}
		if len(mods[i].symbols) >= maxSymbols {
			mods[i].truncated = true
			continue
		}
		mods[i].symbols = append(mods[i].symbols, name)
	}
	return mods, f.Machine, nil
}

// isAPISet reports a virtual API set name - a contract the OS satisfies via
// apisetschema.dll, with no file of that name on disk. Resolving one means
// reimplementing the apiset map; naming it and moving on is the honest
// bound.
func isAPISet(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "api-ms-") || strings.HasPrefix(lower, "ext-ms-")
}

// resolve finds a DLL the way the loader's default search does for the cases
// this probe attempts: the importing object's directory, the application's
// directory, then the system directory. PATH and SxS redirection are
// deliberately out of scope - both depend on an environment this probe does
// not have - and a miss is recorded as a nameless path rather than guessed.
func (p *prober) resolve(name, objDir, appDir, sysDir string) string {
	for _, dir := range []string{objDir, appDir, sysDir} {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		if p.isFile(candidate) {
			return candidate
		}
	}
	return ""
}

func (p *prober) isFile(path string) bool {
	key := strings.ToLower(path)
	p.mu.Lock()
	hit, ok := p.statCache[key]
	p.mu.Unlock()
	if ok {
		return hit
	}
	fi, err := os.Stat(path)
	hit = err == nil && fi.Mode().IsRegular()
	p.mu.Lock()
	p.statCache[key] = hit
	p.mu.Unlock()
	return hit
}

// systemDir picks System32 or SysWOW64 by the binary's machine type: a
// 32-bit process on a 64-bit OS is redirected to SysWOW64, and handing it
// System32's 64-bit DLLs would name files it cannot load.
func systemDir(machine uint16) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		return ""
	}
	if machine == pe.IMAGE_FILE_MACHINE_I386 {
		wow := filepath.Join(root, "SysWOW64")
		if fi, err := os.Stat(wow); err == nil && fi.IsDir() { // #nosec G703 -- %SystemRoot% plus a constant
			return wow
		}
	}
	return filepath.Join(root, "System32")
}

// Stats says what a ProbeAll actually did, so a surprising result is a
// diagnosis rather than a guessing game.
type Stats struct {
	// Files is how many paths were asked about; Probed how many were
	// actually parsed before any deadline; PE how many parsed as PE
	// binaries; Linked how many carried at least one import.
	Files, Probed, PE, Linked int

	// FirstError is the first parse failure verbatim, nil when every file
	// parsed. One representative error names the class of problem.
	FirstError error

	// Aborted is set when the context expired before every path was
	// probed. The links gathered so far are still returned: partial truth
	// beats silence, but the caller must say the truth is partial.
	Aborted bool
}

// ProbeAll probes every path, sharing one parse cache across all of them -
// the Windows equivalent of the ELF walk's ProbeAll, except the caller hands
// in the file list the MFT enumeration already built instead of walking
// anything twice.
//
// The parse phase runs in parallel because on a machine with real-time
// antivirus every file open is intercepted, and that interception dominates
// the runtime; the per-binary resolution afterwards is pure map lookups.
// Parallelism 0 means a quarter of the CPUs, the politeness default the
// extractor uses for the same reason.
func ProbeAll(ctx context.Context, paths []string, opts Options, parallelism int) (map[string][]Link, Stats) {
	if parallelism <= 0 {
		if parallelism = runtime.NumCPU() / 4; parallelism < 1 {
			parallelism = 1
		}
	}

	// The garbage collector is bounded process-wide by sched.Apply in
	// background mode; a local GOMAXPROCS clamp here would only fight it.

	p := newProber()
	p.ctx = ctx
	p.polite = opts.Polite

	var done int64
	queue := make(chan string)
	var wg sync.WaitGroup
	for w := 0; w < parallelism; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range queue {
				// The pacing lives inside imports, next to the parse it
				// matches, so the sequential phase pays it too.
				p.imports(path)
				atomic.AddInt64(&done, 1)
			}
		}()
	}

	// A probe over a whole machine is minutes of wall clock; a minutes-long
	// silence is indistinguishable from a hang, and an operator who cannot
	// tell the difference kills the run.
	progressDone := make(chan struct{})
	if opts.Logf != nil && len(paths) > 1000 {
		go func() {
			tick := time.NewTicker(30 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-progressDone:
					return
				case <-tick.C:
					opts.Logf("pe: still probing (%d of %d files)",
						atomic.LoadInt64(&done), len(paths))
				}
			}
		}()
	}

	for _, path := range paths {
		if ctx.Err() != nil {
			break
		}
		queue <- path
	}
	close(queue)
	wg.Wait()
	close(progressDone)

	// Assembly runs to completion REGARDLESS of the deadline: the parses
	// already happened, resolution stats are cached, and the deadline
	// only stops the prober from starting new parses for transitive
	// resolution. The links from every file parsed in time are delivered.
	stats := Stats{Files: len(paths), Probed: int(atomic.LoadInt64(&done))}
	out := make(map[string][]Link)
	for _, path := range paths {
		if _, _, isPE := p.imports(path); isPE {
			stats.PE++
		}
		links, err := p.probe(path, opts)
		if err != nil || len(links) == 0 {
			continue
		}
		out[path] = links
	}
	stats.Aborted = ctx.Err() != nil
	stats.Linked = len(out)
	stats.FirstError = p.firstErr
	return out, stats
}

// politePause matches the rest to the work: a pause as long as the parse
// took gives everything else on the machine - the antivirus included - half
// the wall clock. Bounded below so a cached parse still yields the CPU, and
// above so one slow file cannot stall the probe for seconds.
func politePause(parse time.Duration) time.Duration {
	const (
		floor = 200 * time.Microsecond
		cap   = 25 * time.Millisecond
	)
	if parse < floor {
		return floor
	}
	if parse > cap {
		return cap
	}
	return parse
}

func pause(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
