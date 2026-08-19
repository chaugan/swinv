# `swinv` — Local Software Inventory Collector

**Specification of record.**

> This document began as a build specification written before implementation. It has
> been updated to describe the system **as actually built and measured**, because
> several of the original assumptions turned out to be wrong in ways that matter.
> Where reality diverged from the original plan, the divergence is called out
> explicitly with the evidence — those notes are the most valuable part of this
> document and should survive future edits.
>
> The tool was originally specified under the name `invd`. It ships as **`swinv`**.
> `grype` was considered and rejected: that name belongs to Anchore's vulnerability
> scanner, which §1 names as the separate *downstream* consumer of this tool's
> CycloneDX output. Naming both the producer and the consumer `grype` would have
> made every example ambiguous.

---

## 1. What this is

A single-binary Linux command-line tool that scans the machine it runs on,
enumerates every piece of installed software it can find (name + version + as much
identifying metadata as possible), and writes the result to **local JSON and CSV
files on that machine**.

That is the whole product. There is no server, no agent daemon, no network
transmission, no database. Files land on disk; something else (rsync, Ansible,
a log shipper, a human) is responsible for collecting them later.

### Goals

1. **Complete coverage.** OS packages, language-ecosystem packages, and loose
   binaries that were never installed by a package manager.
2. **Zero deployment friction.** One static binary, `scp` it anywhere, run it.
   No runtime, no interpreter, no shared libraries, no config file required.
3. **Stable machine-readable output.** A versioned JSON schema and a flat CSV
   that can be loaded straight into a spreadsheet or a database.
4. **Fully open source**, with a licence position that is deliberate rather than
   accidental (see §3).

### Non-goals — do not build these

- No central server, API client, or "phone home" of any kind.
- No configuration management, patching, or remediation.
- No vulnerability scanning. (Anchore's `grype` consumes our CycloneDX output if the
  user wants that later. Do not embed it.)
- No Windows or macOS support in v1. Design the code so it is not *hostile* to
  them, but do not spend effort on them.
- No TUI, no progress bars beyond simple stderr status lines.

---

## 2. Locked design decisions

These were decided by the project owner. Do not revisit them.

| Decision | Choice |
|---|---|
| Language | **Go** |
| Detection scope | **Everything** — OS packages, language packages, and loose/unmanaged binaries |
| Package parsers | **Import Syft as a library** (`github.com/anchore/syft`), do not shell out to the `syft` CLI, do not hand-roll parsers |
| Output | Local files only: JSON + CSV (plus optional CycloneDX and NDJSON) |
| Distribution | Single static binary, `CGO_ENABLED=0` |
| Module path | `github.com/chaugan/swinv` |

The rationale for importing Syft rather than wrapping the CLI: it gives ~40
package ecosystems and the binary-classifier cataloger on day one, it is
Apache-2.0 so it imposes no licence obligation, and calling it in-process avoids
subprocess overhead and JSON round-tripping.

> **This decision was re-examined and upheld.** The question "would this be quicker
> in Rust?" was raised during implementation. It would not: the runtime is dominated
> by filesystem walking and by Syft's parsing and file-ownership graph construction,
> not by language overhead. A preflight walk that lstats ~500k files completes in
> ~4 s in Go. Rewriting in Rust would mean reimplementing ~40 ecosystem parsers and
> the binary classifier from scratch, and there is no Rust equivalent with
> comparable coverage. The one place a rewrite would genuinely win is memory
> (see §10) — an expensive way to buy RAM.

---

## 3. Licensing — required reading

The project is **Apache-2.0**, matching its primary dependency.

- **Syft is Apache-2.0.** Importing it imposes no copyleft. Its `LICENSE` and
  `NOTICE` attribution are retained.
- **Do not import any GPL or AGPL Go module** into this binary. Linking GPL code
  into the binary would force the entire combined work under the GPL. If you find
  yourself wanting functionality that only exists in a GPL library, stop and
  surface it as a question rather than importing it.
- Apache-2.0 was chosen over MIT/BSD deliberately: it carries an express patent
  grant and patent-retaliation clause, and it is the licence enterprise legal
  review recognises without discussion.

Deliverables, all present:

- `LICENSE` — the Apache-2.0 text, verbatim, followed by a COPYRIGHT block.
  **The project is community-owned**: copyright is `The swinv Authors`, held
  collectively by contributors, with no CLA and no copyright assignment. The
  consequence is accepted deliberately — `swinv` cannot be relicensed or
  dual-licensed without every contributor's agreement.
  Note the Apache appendix template inside `LICENSE` intentionally still reads
  `Copyright [yyyy] [name of copyright owner]`: that is instructional boilerplate
  showing others how to apply the licence, and the licence text must stay
  verbatim. Do not "fill it in".
- `AUTHORS` — the contributor list that `LICENSE` refers to.
- `NOTICE` — attribution for Anchore/Syft and the other direct dependencies.
- `THIRD_PARTY_LICENSES.md` — generated by `make licenses`, checked into the repo.
  Currently 278 dependencies: 122 Apache-2.0, 85 MIT, 48 BSD-3-Clause, 10 MPL-2.0,
  7 BSD-2-Clause, and a small tail. **Zero GPL, AGPL, or LGPL.**

### The CI licence gate

`make license-check` fails the build if any dependency's licence is GPL, AGPL,
LGPL, or unidentified. This is a hard requirement, not a nice-to-have — it is the
mechanism that keeps the licence position from drifting.

**`licenses-allowlist.txt` exists and its scope is deliberately narrow.**
`go-licenses` classifies by pattern-matching the LICENSE file, and two dependencies
ship permissive licences in prose it cannot recognise:

- `github.com/xi2/xz` — its LICENSE declares the files **public domain**.
- `modernc.org/mathutil` — its LICENSE is the verbatim **3-clause BSD** text.

Both were read by a human and recorded in the allowlist with the licence found and
where it was read from. **An allowlist entry only suppresses an "Unknown"
classification; it can never suppress a detected GPL/AGPL/LGPL.** This is enforced,
not merely documented — the gate was negative-tested by injecting a GPL dependency
(correctly failed) and by flipping an allowlisted module to LGPL (**also correctly
failed**). Preserve that property in any future edit to the gate.

---

## 4. Toolchain — read before `go get`

There is a real, recently-encountered trap here.

- Syft `v1.51.0` and later declare `go >= 1.26.3` in their `go.mod`. If your Go
  toolchain is older and cannot auto-download a newer one, the build fails with
  `unrecognized import path "golang.org/toolchain"`.

**As built: Go 1.26.6 and Syft v1.51.0, both pinned exactly.** Never `@latest`.

### CGO — and the trap that replaced the old one

`CGO_ENABLED=0` works and produces a genuinely static binary
(`ldd bin/swinv` → "not a dynamic executable"). But the reason is no longer the one
the original spec assumed, and the difference is fatal if you get it wrong:

> **Syft v1.51.0 no longer registers a SQLite driver itself. The consumer must do
> it.** Without a blank import of `modernc.org/sqlite`, `CreateSBOM` does not
> merely skip RPM databases — it **fails outright** with
> `sqlite driver is required for cataloging newer RPM databases`, **even on a host
> with no RPM database at all**. Syft's own `cmd/syft/main.go` does exactly this
> import. Verified against v1.51.0, not speculative.

The driver is pure Go, so `CGO_ENABLED=0` survives. The import lives in
`internal/scan` and is commented as load-bearing. Do not remove it.

Note that `go test -race` requires cgo. That applies to the test step only; the
shipped binary is always built with `CGO_ENABLED=0`. CI does both.

---

## 5. Repository layout

```
swinv/
├── cmd/swinv/
│   ├── main.go                 # wiring, report assembly, exit codes
│   ├── flags.go                # flag parsing and validation
│   ├── memory.go               # --max-memory size parsing + soft limit
│   ├── flags_test.go
│   ├── parsesize_test.go
│   └── golden_test.go          # golden-file, determinism, schema, non-root tests
├── internal/
│   ├── hostfacts/              # machine identity: hostname, machine-id, DMI, kernel, NICs
│   ├── scan/                   # the Syft integration — the only package that imports syft
│   │   ├── scan.go             # GetSource + CreateSBOM + conversion
│   │   ├── options.go          # exclusion construction, mountinfo parsing
│   │   ├── preflight.go        # symlink quarantine (see §8)
│   │   └── hash.go             # --hash content digests
│   ├── model/                  # output types + schema version. Stdlib only.
│   └── output/                 # JSON, CSV, NDJSON, CycloneDX writers + atomic writes
├── packaging/
│   ├── swinv.service           # systemd oneshot unit
│   ├── swinv.timer             # daily timer with randomised delay
│   └── swinv.8                 # man page
├── testdata/
│   ├── rootfs/                 # fixture rootfs for integration tests
│   └── golden/                 # checked-in golden JSON and CSV
├── .github/workflows/ci.yml
├── .golangci.yml
├── Makefile
├── licenses-allowlist.txt
├── LICENSE  NOTICE  THIRD_PARTY_LICENSES.md  README.md
```

**Architectural rule:** `internal/scan` is the *only* package permitted to import
Syft. Everything downstream operates on `internal/model` types. This keeps a Syft
API break contained to one package, and leaves the door open to adding a second
collection backend later without touching the writers.

A consequence worth stating: **the CycloneDX writer does not use Syft's encoder.**
It builds its document from `model.Report` via `github.com/CycloneDX/cyclonedx-go`
(Apache-2.0), because using Syft's encoder would drag Syft into `internal/output`
and break the rule.

---

## 6. Data model

Defined in `internal/model`. Field names in JSON are `snake_case`.

```go
const SchemaVersion = "1.1"
```

**1.0 → 1.1** added `Component.SHA256` (§9 `--hash`) and `Report.Delta`
(§9 `--since`). Both are additive and omitted when unused, so a 1.0 consumer still
parses a 1.1 document.

```go
type Report struct {
    SchemaVersion string      `json:"schema_version"`
    Tool          Tool        `json:"tool"`
    Host          Host        `json:"host"`
    Scan          ScanMeta    `json:"scan"`
    Delta         *Delta      `json:"delta,omitempty"`
    Components    []Component `json:"components"`
}

type Tool struct {
    Name        string `json:"name"`         // "swinv"
    Version     string `json:"version"`      // set via -ldflags
    Commit      string `json:"commit,omitempty"`
    SyftVersion string `json:"syft_version"` // from debug.ReadBuildInfo()
}

type Host struct {
    Hostname       string   `json:"hostname"`
    FQDN           string   `json:"fqdn,omitempty"`
    MachineID      string   `json:"machine_id,omitempty"`      // /etc/machine-id
    BootID         string   `json:"boot_id,omitempty"`
    OSID           string   `json:"os_id,omitempty"`           // os-release ID
    OSVersionID    string   `json:"os_version_id,omitempty"`
    OSPrettyName   string   `json:"os_pretty_name,omitempty"`
    KernelRelease  string   `json:"kernel_release,omitempty"`
    Architecture   string   `json:"architecture,omitempty"`
    Virtualization string   `json:"virtualization,omitempty"`
    SystemVendor   string   `json:"system_vendor,omitempty"`   // DMI
    ProductName    string   `json:"product_name,omitempty"`    // DMI
    ProductSerial  string   `json:"product_serial,omitempty"`  // DMI, root-only
    ProductUUID    string   `json:"product_uuid,omitempty"`    // DMI, root-only
    IPv4           []string `json:"ipv4,omitempty"`
    IPv6           []string `json:"ipv6,omitempty"`
    MACs           []string `json:"macs,omitempty"`
}

type ScanMeta struct {
    StartedAt   time.Time `json:"started_at"`    // RFC3339, UTC
    FinishedAt  time.Time `json:"finished_at"`
    DurationMS  int64     `json:"duration_ms"`
    Root        string    `json:"root"`
    Excluded    []string  `json:"excluded,omitempty"`
    Catalogers  []string  `json:"catalogers,omitempty"`
    RanAsRoot   bool      `json:"ran_as_root"`
    Incomplete  bool      `json:"incomplete"`    // true if any cataloger errored, §11
    Warnings    []string  `json:"warnings,omitempty"`
}

type Component struct {
    Name      string   `json:"name"`
    Version   string   `json:"version"`
    Type      string   `json:"type"`               // "deb", "rpm", "python", "binary", ...
    Language  string   `json:"language,omitempty"`
    PURL      string   `json:"purl,omitempty"`
    CPEs      []string `json:"cpes,omitempty"`
    Licenses  []string `json:"licenses,omitempty"` // SPDX IDs where known
    Locations []string `json:"locations,omitempty"`// real paths on disk
    FoundBy   string   `json:"found_by,omitempty"` // originating Syft cataloger
    SHA256    string   `json:"sha256,omitempty"`   // only with --hash, see §9
    Change    string   `json:"change,omitempty"`   // only with --since, see §9
}

// Delta is populated by --since.
type Delta struct {
    Since        string      `json:"since"`
    Only         bool        `json:"delta_only,omitempty"`
    BaselineAt   time.Time   `json:"baseline_at"`
    BaselineHost string      `json:"baseline_host,omitempty"`
    Added        []Component `json:"added,omitempty"`
    Removed      []Component `json:"removed,omitempty"`
    Changed      []Change    `json:"changed,omitempty"`
}

type Change struct {
    Name        string `json:"name"`
    Type        string `json:"type"`
    FromVersion string `json:"from_version"`
    ToVersion   string `json:"to_version"`
    PURL        string `json:"purl,omitempty"`
}
```

### Identity and ordering rules

- **PURL is the canonical identifier.** It is the join key if these files are
  ever merged across machines. Always populate it when Syft provides one.
- **Deduplicate** components on the tuple `(Name, Version, Type, PURL)`. Syft can
  legitimately report the same package from two catalogers. When merging
  duplicates, union the `Locations`, `CPEs`, and `Licenses` sets; for single-valued
  fields (`Language`, `FoundBy`, `SHA256`) the first non-empty value wins, so the
  result does not depend on cataloger completion order.
- **Sort deterministically** before writing: by `Type`, then `Name`, then
  `Version`, then `PURL`. Two runs on an unchanged machine must produce
  byte-identical output apart from the timestamps in `ScanMeta`. This is tested,
  including an order-independence test that shuffles the input 50 times.
- Sort every string slice (`Locations`, `CPEs`, `Licenses`, `IPv4`, `MACs`) too.
- **Delta matching is on `(Name, Type)` only — deliberately not on version.** A
  package that was upgraded must read as one `changed` entry, not as a removal plus
  an unrelated addition. That is the entire point of diffing daily inventories.

### CSV format

One row per component, header row always present, RFC 4180 quoting, `\n` line
endings, UTF-8, no BOM. Host identity is repeated on every row so the file is
useful standalone when concatenated across machines.

Columns, in exactly this order (17 as of schema 1.1):

```
hostname,machine_id,os_id,os_version_id,architecture,scanned_at,
name,version,type,language,purl,cpes,licenses,locations,found_by,sha256,change
```

`cpes`, `licenses`, and `locations` are multi-valued: join with `;` inside the
single CSV field. `scanned_at` is `ScanMeta.StartedAt` in RFC3339 UTC.

**`sha256` and `change` are always present, even when `--hash` and `--since` were
not used**, so the column shape never varies with flags. That is what keeps CSVs
concatenable across machines and across runs; do not make them conditional.

---

## 7. `internal/hostfacts`

Pure standard library. **Do not shell out to `hostnamectl`, `dmidecode`, `ip`, or
`uname`** — read the kernel interfaces directly so the binary stays dependency-free.

| Field | Source | Notes |
|---|---|---|
| Hostname | `os.Hostname()`, or `<root>/etc/hostname` for a fixture root | |
| FQDN | reverse/CNAME lookup on the primary IP | Best-effort, ≤2s timeout, never fatal; skipped when the root is not `/` so tests stay hermetic |
| MachineID | `/etc/machine-id`, fall back to `/var/lib/dbus/machine-id` | |
| BootID | `/proc/sys/kernel/random/boot_id` | |
| OS\* | Parse `/etc/os-release`, fall back to `/usr/lib/os-release` | Syft's `LinuxDistribution` is preferred when populated; this is the fallback |
| KernelRelease | `/proc/sys/kernel/osrelease` | |
| Architecture | `runtime.GOARCH` | |
| Virtualization | `/sys/class/dmi/id/{product_name,sys_vendor}` + `/sys/hypervisor/type` | Best-effort; also detects containers via `/.dockerenv` and `/proc/1/cgroup`. Empty is acceptable |
| SystemVendor, ProductName | `/sys/class/dmi/id/{sys_vendor,product_name}` | |
| ProductSerial, ProductUUID | `/sys/class/dmi/id/{product_serial,product_uuid}` | Root-only; on `EACCES` leave empty and do **not** warn |
| IPv4/IPv6/MACs | `net.Interfaces()` | Skip loopback, down interfaces, and link-local addresses |

Every field is optional. A missing or unreadable file yields an empty value, never
an error and never a log line. The one exception: if `--require-host-id` is passed
and `MachineID` is empty, exit non-zero.

`/etc/os-release` parsing handles quoted values, single quotes, escaped characters
inside double quotes, blank lines, `#` comments, CRLF, and malformed lines.

Firmware placeholder strings (`To Be Filled By O.E.M.`, `Default string`,
`System Serial Number`, the all-zero UUID) are mapped to empty. They look like real
data once inventories are aggregated across a fleet.

---

## 8. `internal/scan` — Syft integration

**Verified against `github.com/anchore/syft` v1.51.0.** If you pin a newer Syft,
re-verify against `syft/create_sbom.go`, `syft/get_source.go`,
`syft/create_sbom_config.go`, and `syft/cataloging/`.

### Entry points

```go
func GetSource(ctx context.Context, userInput string, cfg *GetSourceConfig) (source.Source, error)
func CreateSBOM(ctx context.Context, src source.Source, cfg *CreateSBOMConfig) (*sbom.SBOM, error)
```

Force the directory provider with `WithSources("dir")`. Without it, Syft will try
to interpret the input as a container image reference first, which is wasted work
and can produce confusing errors.

Baseline configuration as built:

```go
syft.DefaultCreateSBOMConfig().
    WithTool("swinv", version).
    WithoutFiles().
    WithParallelism(opts.Parallelism).
    WithSearchConfig(cataloging.DefaultSearchConfig().WithScope(source.SquashedScope)).
    WithRelationshipsConfig(cataloging.DefaultRelationshipsConfig().
        WithPackageFileOwnership(opts.FileOwnership)).
    WithCatalogerSelection(sel)
```

`source.SquashedScope` is correct for a live filesystem. The other scopes
(`AllLayersScope`, `DeepSquashedScope`) are container-image concepts — do not use them.

### Cataloger selection

Default selection when `--catalogers` is empty:

```go
cataloging.NewSelectionRequest().
    WithDefaults(pkgcataloging.InstalledTag, pkgcataloging.DirectoryTag)
```

The binary classifier, ELF-package, PE-package, JVM-distribution, and Linux-kernel
catalogers all carry the `directory` tag, so a plain directory scan already covers
the "loose binaries" requirement. A non-empty `--catalogers` is passed through
`SelectionRequest.WithExpression`.

The `sbom` cataloger is explicitly *not* evidence of installed software (it parses
SBOM files found on disk) and stays disabled by default.

### Relationships

Keep `ExcludeBinaryPackagesWithFileOwnershipOverlap: true`. It is what stops the
binary classifier from reporting `/usr/bin/python3.11` as a separate "binary"
component when the `python3.11` deb already claims that file.

`PackageFileOwnership` is exposed as `--no-file-ownership`, **defaulted to on**.
See §10 for the measured effect — it is a speed lever, *not* a memory lever, which
is the opposite of what it looks like.

### Two Syft behaviours that will bite you

**1. Syft mutates the exclusion slice you hand it, in place.**
`directorysource.getDirectoryExclusionFunctions` does
`exclusions[idx] = root + exclusion`, rewriting `./proc/**` to
`/abs/root/proc/**`. Passing our own slice corrupted `ScanMeta.Excluded`, because
it shared the same backing array. **Always pass a copy.**

**2. One unreadable symlink aborts the entire scan.** This is the single most
important thing in this document.

Observed on a live Ubuntu host running unprivileged: **zero components** after a
five-minute scan, with

```
unable to index filesystem path="/root/.local/share/uv/.../python3.12":
  lstat /root/.local: permission denied
```

Mechanism ([anchore/syft#3286](https://github.com/anchore/syft/issues/3286), open):
Syft's indexer tolerates ordinary per-file permission errors during the walk. But
when it meets a symlink it queues the link's **target** as an *additional root*
(`addSymlinkToIndex` returns the target unless `os.Stat` reports `ENOENT` — a
permission error still queues it). Each additional root is then resolved with
`filepath.EvalSymlinks` **before any path-index visitor runs**, and
`indexAllRoots` treats a failure there as fatal to the whole scan. A single
virtualenv symlink, `/opt/.../.venv12/bin/python -> /root/.local/.../python3.12`,
was enough.

**Excluding the target does not help.** This was tested, not assumed:
`--exclude './root/**'` failed identically, because the fatal resolution happens
before exclusions are consulted.

The fix is `internal/scan/preflight.go`: an lstat-only walk, run before Syft is
handed anything, that finds symlinks whose target cannot be resolved and excludes
**the links themselves**, so the indexer never queues the bad root. This is what
took the scan from 0 to 14,190 components. Quarantined links are recorded in
`ScanMeta.Excluded` and counted in `ScanMeta.Warnings`.

The preflight's exclusion matcher deliberately only honours `./`-anchored
patterns. `*/` and `**/` patterns are ignored there, so those paths are still
walked. That is the safe direction to be wrong in: over-skipping would let through
exactly the symlink the pass exists to catch. Extra lstat calls are cheap; a lost
scan is not.

Remove the preflight only when upstream fixes #3286.

### Exclusion patterns — hard requirement

`source.ExcludeConfig{Paths: []string{...}}`. Patterns **must** begin with `./`,
`*/`, or `**/`. Anything else fails at source construction. Validate them at
startup and build them programmatically; do not let a user typo produce that error.

Defaults when the scan root is `/`:

```
./proc/**    ./sys/**     ./dev/**       ./run/**      ./tmp/**
./var/tmp/** ./var/cache/**              ./var/log/**  ./var/spool/**
./var/crash/**              ./var/backups/**           ./var/lib/systemd/coredump/**
./var/lib/docker/**         ./var/lib/containers/**    ./var/lib/containerd/**
./var/lib/kubelet/pods/**   ./mnt/**     ./media/**    ./lost+found/**
./swapfile   ./swap.img
**/.git/**   **/__pycache__/**           **/.cache/**
./home/**    ./root/**     (unless --include-home)
```

Additionally, skip filesystems that are not local: read `/proc/self/mountinfo`
and exclude any mount point whose filesystem type is in
`{nfs, nfs4, cifs, smb3, fuse.sshfs, fuse.rclone, autofs, overlay, squashfs, tmpfs, devtmpfs, proc, sysfs, cgroup, cgroup2}`.
This is the single biggest cause of a scan taking hours instead of minutes, and it
is not something Syft does for you. `--no-auto-exclude-mounts` disables it. The
final exclusion list is always recorded in `ScanMeta.Excluded`.

Mount points are octal-escaped by the kernel (`\040` for space); unescape them.

### Snap vs the squashfs rule — a resolved contradiction

The original spec said two things that conflict: auto-exclude every non-local
filesystem (listing `squashfs`), *and* include `/snap` by default. **Snaps are
squashfs loop mounts.** On the test host all seven squashfs mounts were snaps, so
the first rule silently defeated the second and made `--no-snap` a no-op.

Resolution: `squashfs` stays in the non-local set, but mount points under `/snap`
and `/var/lib/snapd/snap` are **carved out** of that rule unless `--no-snap` was
passed. A squashfs image mounted anywhere else — an ISO, an appliance payload — is
still excluded, which is correct: that is not installed software.

### `/home` and `/root` are excluded by default

The original spec left this open (old §16.4). It is now decided: **excluded, with
`--include-home` to opt in.**

Evidence: on the development host `/home` alone was 508,687 files and 40 GB across
86 `node_modules` trees — more than the entire rest of the filesystem combined.
A full scan with home included does not finish in a comparable time. Home
directories are also per-user, high-churn, and privacy-sensitive, none of which is
true of the machine's own software. For a fleet inventory feeding asset management,
the managed system-wide surface is the useful signal.

The skip is never silent: the paths appear in `ScanMeta.Excluded` and a warning is
written to `ScanMeta.Warnings`.

### Reading results

Iterate with `sbom.Artifacts.Packages.Enumerate()`, which yields `pkg.Package`
over a channel.

For `Locations`, prefer `location.RealPath`; fall back to `location.AccessPath`
when `RealPath` is empty. Strip the scan-root prefix so paths are absolute system
paths regardless of `--root`.

`Artifacts.LinuxDistribution` is a `*linux.Release`. **It may be nil** — always
nil-check before dereferencing, and fall back to `hostfacts`. This is not
theoretical: scanning `/usr/bin` produces a nil distribution.

`Artifacts.Unknowns` records paths Syft saw but could not identify. Surface the
*count* in `ScanMeta.Warnings`, not the full list.

### Logging

Syft is silent by default (discard logger). **Leave `syft.SetLogger()` and
`syft.SetBus()` unset.** Emit our own stderr status lines instead. `log/slog` from
the standard library is sufficient; do not pull in a logging framework.

---

## 9. CLI

```
swinv [flags]
```

| Flag | Default | Meaning |
|---|---|---|
| `--root PATH` | `/` | Filesystem root to scan |
| `--out DIR` | `/var/lib/swinv` | Output directory |
| `--output-mode MODE` | `dated` | `dated`, `overwrite`, or `timestamped` — see below |
| `--name TEMPLATE` | *(from `--output-mode`)* | Output basename; `{hostname}`, `{machine_id}`, `{date}`, `{datetime}` |
| `--format LIST` | `json,csv` | Comma-separated: `json`, `csv`, `ndjson`, `cyclonedx-json` |
| `--stdout` | false | Write to stdout instead of files; requires exactly one `--format` |
| `--latest-symlink` | true | Maintain `{hostname}-latest.{ext}` symlinks in `--out` |
| `--exclude GLOB` | — | Repeatable; appended to the defaults. Must start with `./`, `*/` or `**/` |
| `--no-auto-exclude-mounts` | false | Do not auto-exclude non-local filesystems |
| `--no-snap`, `--no-flatpak` | false | Exclude those trees |
| `--include-home` | false | Also scan `/home` and `/root` |
| `--hash` | false | Record a SHA-256 per component (see below) |
| `--since PATH` | — | Compare against a previous report and emit a delta |
| `--delta-only` | false | With `--since`, emit only the changed components |
| `--max-memory SIZE` | — | Soft memory limit, e.g. `1536MiB` |
| `--catalogers EXPR` | — | Passed to `SelectionRequest.WithExpression` |
| `--no-file-ownership` | false | Faster, but reintroduces binary/package duplicates |
| `--parallelism N` | `0` | `0` = `runtime.NumCPU()` |
| `--timeout DURATION` | `30m` | Whole-run deadline via `context.WithTimeout` |
| `--require-host-id` | false | Fail if `/etc/machine-id` is unreadable |
| `--quiet` | false | Suppress stderr status output |
| `--verbose` | false | Per-stage timing to stderr |
| `--version` | — | Print version, commit, Syft version; exit 0 |

Standard library `flag` package. **No Cobra, no Viper** — this is a single-command
tool and the dependency is not justified.

### Output modes

`--output-mode` selects the default `--name` template. An explicit `--name` always wins.

| Mode | Template | Behaviour |
|---|---|---|
| `dated` *(default)* | `{hostname}-{date}` | One file per day; re-running the same day replaces it |
| `overwrite` | `{hostname}` | One fixed file, replaced atomically every run |
| `timestamped` | `{hostname}-{datetime}` | A brand-new file for every run |

### `--hash`

Records a SHA-256 of each component's primary on-disk file. Off by default: it
reads every such file in full.

**Files backing more than one component are deliberately not hashed.** Most debs
cite `/var/lib/dpkg/status` as their evidence; digesting it would give every
package on the machine an identical hash *and* make all of them appear changed
whenever any single package changed — precisely backwards for change detection.
The count skipped is reported in `ScanMeta.Warnings`. Files over 512 MB and
anything that is not a regular file are skipped.

### `--since` / `--delta-only`

`--since` adds the `Delta` block. By default the full inventory is still written
alongside it, so the file remains a self-contained inventory. `--delta-only` drops
the unchanged components.

**A `--delta-only` report is marked (`delta.delta_only`) and is refused as a future
`--since` baseline**, exiting 2. Diffing against a diff would report every
unchanged package as newly added. Comparing against a *different machine's* report
is permitted but recorded as a warning.

### Behaviour notes

- Create `--out` with mode `0755` if missing; write files `0644`.
- **Write atomically:** write to `<target>.tmp-<pid>` in the same directory,
  `fsync` the file, `rename`, then `fsync` the directory. Open the temp file
  `O_EXCL` so a planted symlink cannot redirect the write. Clean up on any error
  path. Verified: `kill -9` at four different points left no partial `.json`/`.csv`.
- Update the `-latest` symlink atomically too (temp symlink, then rename).
- Running as non-root is fully supported and must not error. It will miss
  root-only paths and DMI serials; set `ScanMeta.RanAsRoot = false` and add a
  warning.

---

## 10. Performance — measured, not aspirational

The original targets were **< 2 s** for OS packages only, **< 60 s** for a default
full scan, and **< 512 MB** peak RSS, on "a typical server (~2000 dpkg packages,
SSD, 4 cores)".

**None of these are met on the development host, and two of them are not reachable
as originally conceived.** The measured numbers, on Ubuntu 26.04, 8 cores, ~1M
files, unprivileged:

| Configuration | Wall | Peak RSS |
|---|---|---|
| default | 348 s | 2271 MB |
| `--no-file-ownership` | 233 s | 2414 MB |
| `--parallelism 2` | 322 s | 2197 MB |
| `--parallelism 1 --no-file-ownership` | 325 s | 1735 MB |
| **`--max-memory 1536MiB`** | **304 s** | **1580 MB** |
| `--max-memory 768MiB` | 546 s | 1337 MB |
| `--max-memory 768MiB --parallelism 1` | 615 s | 1085 MB |

Every row produced the same inventory (14,190 components).

Findings that should shape any future optimisation work:

1. **The host is not "typical".** It carries a developer checkout in `/opt`
   (156k files, node_modules) on top of `/usr` (118k) and `/var` (227k). A server
   with ~2000 dpkg packages and no source trees is a different shape entirely.
   Re-measure before concluding the tool is slow in production.

2. **`--catalogers os` does not make scanning cheap.** Syft indexes the entire
   filesystem when it builds the directory resolver, *before* cataloger selection
   is applied. Narrowing catalogers narrows parsing, not the walk. Measured at
   135 s, against a 2 s target. **The < 2 s target is not achievable this way.**

3. **The obvious fix for that is a trap.** Excluding `/usr`, `/opt` and friends
   gets an OS-only scan to ~4 s — and silently drops deb licence coverage from
   **99% to 0%**, because dpkg licences are read from `/usr/share/doc/*/copyright`.
   This optimisation was implemented, measured, and **rejected**. Do not
   reintroduce it without solving the licence problem.

4. **`--no-file-ownership` is not a memory lever.** It is ~33% faster but uses
   slightly *more* memory. Use it to buy speed, never RAM.

5. **`--max-memory 1536MiB` beat the default on both axes** — 30% less memory and
   13% faster. A smaller heap means less to scan and better cache locality, so the
   usual space-for-time trade does not appear until the limit gets genuinely tight.
   It is not a default (a fixed cap is wrong on unknown hardware) but it is the
   single best one-flag change, and the systemd unit carries it as a commented
   example.

6. **The footprint is Syft's in-memory path index, not our code.** The effective
   levers are the ones that shrink the walk (exclusions) or bound the heap
   (`--max-memory`). Micro-optimising the conversion path is pointless.

`make bench` runs the binary against `testdata/rootfs` and prints wall time and
peak RSS.

---

## 11. Errors and exit codes

| Code | Meaning |
|---|---|
| 0 | Success; a complete inventory was written |
| 1 | Partial success; output written but `ScanMeta.Incomplete = true` |
| 2 | Usage error (bad flag, bad exclusion pattern, conflicting options, unusable `--since` baseline) |
| 3 | Fatal: could not construct the source, or could not write output |
| 4 | Timeout exceeded |

A single cataloger failing must **never** abort the run. Record it in
`ScanMeta.Warnings`, set `Incomplete = true`, write the output you have, and exit 1.
An inventory missing one ecosystem is far more useful than no inventory.

Context failures are wrapped so `errors.Is(err, context.DeadlineExceeded)` works on
the returned error — that is what lets the caller distinguish exit 4 from exit 3.

All human-readable output goes to **stderr**. Only `--stdout` data goes to stdout.

---

## 12. Testing

108 test functions, ~3,300 lines of test code. All pass under `go test -race ./...`.

1. **Unit tests** for `os-release` parsing (quoting, escapes, comments, blank
   lines, CRLF, malformed lines), mountinfo parsing (octal-escaped mount points,
   the optional-fields `-` separator, malformed lines, fs-type filtering),
   exclusion-pattern construction and validation, CSV escaping (values containing
   `,` `"` newline and non-ASCII), dedup/merge logic, the deterministic sort, delta
   computation, and content hashing.
2. **A golden-file test**: a fixture rootfs in `testdata/rootfs` containing a
   miniature `var/lib/dpkg/status`, `dist-packages`, and a `node_modules` tree;
   scanned and compared against checked-in golden JSON and CSV. Regenerate with
   `make golden` (`SWINV_UPDATE_GOLDEN=1`).
3. **A determinism test**: scan the fixture twice, assert byte equality after
   blanking the `ScanMeta` timestamps, across all four output formats.
4. **A non-root test**: assert exit 0, output produced, the warning recorded, and
   no temp files left behind.
5. **A licence-compliance gate** in CI (§3), negative-tested in both directions.

Tests that must not be weakened, because each one encodes a bug that actually
happened:

- `TestQuarantineSymlinks` — the zero-component failure (§8).
- `TestSnapMountsSurviveTheSquashfsRule` — the spec self-contradiction (§8).
- `TestHashComponentsSkipsSharedEvidenceFiles` — the shared-digest trap (§9).
- `TestNormalizeIsOrderIndependent` — the determinism guarantee (§6).
- `TestLoadBaselineRejectsNonReports` — the delta-of-a-delta trap (§9).

`go vet ./...` and `golangci-lint run` are clean. Note that `misspell` is
deliberately **not** enabled: the codebase writes British prose in comments but
must use the US spellings baked into the Go and Syft APIs (`cataloging`,
`Artifacts`, `Normalize`). No locale satisfies both, so it only produces false
positives.

---

## 13. Build and packaging

`Makefile` targets: `build`, `test`, `lint`, `golden`, `bench`, `licenses`,
`license-check`, `release`, `clean`.

```sh
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)" \
  -o bin/swinv ./cmd/swinv
```

Cross-compile targets: `linux/amd64`, `linux/arm64`, with a `SHA256SUMS` file
alongside the binaries in `release`.

`packaging/swinv.service` — a `Type=oneshot` unit running
`/usr/bin/swinv --out /var/lib/swinv`, with `ProtectSystem=strict`,
`ReadWritePaths=/var/lib/swinv`, `PrivateTmp=yes`, `NoNewPrivileges=yes`.

> **Do not add `ProtectHome=yes`, `PrivateDevices`, or similar.** The unit must
> still be able to *read* the whole filesystem — that is the tool's entire job.
> Hardening that hides the tree being scanned defeats the purpose.

`packaging/swinv.timer` — `OnCalendar=daily`, `RandomizedDelaySec=3600`,
`Persistent=true`.

---

## 14. Acceptance criteria

Status as built:

- [x] `CGO_ENABLED=0 make build` produces a static `linux/amd64` binary
      (`ldd bin/swinv` → "not a dynamic executable").
- [x] Running `./bin/swinv --out /tmp/inv` on a Debian-family host writes
      `<hostname>-<date>.json` and `.csv` and exits 0.
- [ ] **…in under 60 s.** Not met on the development host — 304–348 s. See §10 for
      why, and why the target may still hold on a real server.
- [x] The JSON validates against the §6 model and includes dpkg packages (2,367),
      Python (208) and Node (3,549) packages, and components with `type: "binary"` (27).
- [x] The same run as a non-root user exits 0 with a warning recorded.
- [x] Two consecutive runs produce byte-identical output apart from `ScanMeta`
      timestamps, across all four formats.
- [x] The CSV parses cleanly with correct column alignment on rows whose licence
      field contains a comma (verified on 14,189 rows, 33 containing `,` or `"`).
- [x] `make licenses` shows no GPL/AGPL/LGPL/unknown dependency.
- [x] `go vet`, `golangci-lint`, and the full race-enabled test suite pass.
- [x] Killing the process mid-write leaves no partial `.json`/`.csv` in `--out`.
- [ ] **Peak RSS < 512 MB.** Not met — 1085 MB is the lowest measured
      configuration. See §10.

---

## 15. Resolved decisions

These were open questions in the original spec. All are now settled; the reasoning
is recorded so they are not silently reopened.

1. **Content hash of discovered binaries** — **built** (`--hash`, opt-in). The
   non-obvious part is that shared evidence files must be skipped; see §9.
2. **Delta mode (`--since previous.json`)** — **built**, with `--delta-only` and a
   guard against using a delta as a baseline; see §9.
3. **Is CycloneDX wanted?** — **yes, kept.** It is the interchange path to
   vulnerability scanners and costs one Apache-2.0 dependency. Note it is the
   largest output format (roughly 2× the JSON).
4. **Should `/home` be scanned by default?** — **no.** See §8 for the evidence.
   `--include-home` opts in.
5. **Name** — `swinv`. `grype` was rejected as a direct collision with the
   downstream tool named in §1.

### Still genuinely open

- **Nothing on the licence.** Settled: Apache-2.0, community-owned, no CLA (§3).
- **Whether to re-measure §10 on a representative server.** Every performance
  conclusion in this document comes from one atypical developer machine. The
  targets may well be met on the hardware this is actually for, and that is worth
  knowing before optimising anything.
