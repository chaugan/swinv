# Windows support - design

> **Status: proposed. None of this is implemented.**
>
> Every other document in `docs/` describes behaviour that ships and has been
> run. This one does not: there is no registry cataloger, no MSI or Appx
> support, and no USN or MFT enumeration. Not one line of it exists in the tree.
>
> What *has* happened since this was written is that the existing Linux
> collector, cross-compiled unchanged, was run on a real Windows 11 machine.
> That found five defects and produced the measurements now marked **Measured**
> throughout. Those sections are evidence; everything else is still reasoning.
>
> The distinction matters when reading the performance discussion below. A
> `swinv.exe` that walks `C:\Program Files` today is the Linux strategy running
> on a platform it was not designed for - it finds files by walking directories,
> because that is where Linux keeps its truth. It is not what this document
> proposes.

Part of the [swinv](../README.md) documentation.

---

## Why build this at all

There is a real answer and a weak one, and it is worth being honest about which
is which.

**The weak answer** is "one tool for both platforms". On its own that is not
enough. [osquery](https://osquery.io) has a Windows `programs` table,
Wazuh's Syscollector inventories Windows packages and hotfixes, and SCCM and
Intune do this at fleet scale with far more polish than this project will.
If all you need is Windows inventory data, use one of those.

**The real answer is air-gapped environments.** Intune and SCCM require a
management plane the host can reach. osquery works offline but its fleet story
assumes a server. `swinv`'s model - one static binary, no daemon, no network,
writes files that something else collects later - is exactly what an isolated
network can actually use. That is the case for building it, and if that
requirement disappears then so does most of the justification.

A secondary benefit follows from the same design: identical JSON, CSV, NDJSON
and CycloneDX from Linux and Windows means one ingestion pipeline, one schema,
one set of queries.

## What already works

Verified, not assumed:

- **The codebase cross-compiles to Windows today.** `CGO_ENABLED=0
  GOOS=windows GOARCH=amd64 go build ./cmd/swinv` succeeds with no changes and
  produces a 110 MB executable. Syft included.
- **Syft already covers Windows executables.** `pe-binary-package-cataloger`
  exists and fires today on Linux; `dotnet-packages-lock-cataloger` and the
  .NET binary cataloger likewise. PE and .NET identification is not new work.
- **`golang.org/x/sys` v0.47.0 is already a dependency**, so
  `x/sys/windows/registry` and `DeviceIoControl` are available without adding
  anything to `go.mod` or to the licence gate.

## What is missing

**Syft has no registry, MSI, Appx/MSIX or winget cataloger.** The entire
"what is installed" half of Windows does not exist in it and has to be written.
That is the long pole - not Go portability, not packaging.

---

## Architecture

One repository, one command, per-OS files selected by build tags. Not a
separate project: that would fork `model`, the writers and the delta logic,
which are the parts worth sharing.

The seam this needs already exists. `internal/scan` is the only package
permitted to import Syft, and everything downstream operates on
`internal/model` types, stated in the spec as existing so that a second
collection backend can be added without touching the writers. Windows is that
second backend.

```
internal/hostfacts/hostfacts_linux.go     /proc, /sys, /etc  (today)
internal/hostfacts/hostfacts_windows.go   registry, WMI      (new)
internal/scan/options_linux.go            mountinfo          (today)
internal/scan/options_windows.go          volumes, reparse   (new)
internal/scan/windows/                    registry, MSI, Appx, USN (new)
internal/output/atomic_windows.go         no directory fsync (new)
cmd/swinv/priv_{linux,windows}.go         Geteuid vs token elevation (new)
```

Unchanged: `internal/model`, all four writers, `ComputeDelta`, the CLI, and the
Syft conversion in `internal/scan/scan.go`.

---

## Where installed software comes from

### Not `Win32_Product`

Microsoft documents that enumerating `Win32_Product` triggers an MSI
consistency check on every installed product. It is slow, it can cause the
installer to **repair and therefore mutate the machine**, and it still only
sees MSI installs. For a tool whose entire posture is passive observation, that
is disqualifying. It must not be used, and this should be a comment in the code
rather than only here, because it is the obvious-looking wrong answer.

### The sources that are needed

| Source | Where | Covers |
|---|---|---|
| ARP, 64-bit | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` | most installed applications |
| ARP, 32-bit on 64-bit | `HKLM\SOFTWARE\WOW6432Node\...\Uninstall` | 32-bit applications |
| ARP, current user | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` | per-user installs |
| ARP, other users | `HKU\<SID>\SOFTWARE\...\Uninstall` | other loaded profiles; needs elevation |
| MSI products and patches | `msi.dll` - `MsiEnumProducts`, `MsiEnumPatches`, `MsiGetProductInfo` | MSI products, and patches, which do **not** appear under the uninstall keys |
| Appx / MSIX | `Windows.Management.Deployment.PackageManager` | Store and modern packaged apps. Enumerate via the API, never by walking `WindowsApps` |
| Hotfixes | CBS: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages` | updates. `Win32_QuickFixEngineering` is an incomplete subset on modern servicing |

**winget is deliberately excluded.** It mostly re-reads ARP and Appx, and it
expects network access. In an air-gapped environment it contributes nothing.

Read from each ARP key: `DisplayName`, `DisplayVersion`, `Publisher`,
`InstallLocation`, `InstallDate`, `WindowsInstaller`, `SystemComponent`,
`UninstallString`. Entries flagged `SystemComponent=1` are hidden from
Add/Remove Programs and should be recorded but marked, not silently dropped.

**`DisplayName` is a trap.** It is localised, and it frequently embeds the
version (`"Foo Bar 3.2.1 (x64)"`). That makes it a poor identity across
machines with different locales, and it will produce spurious `--since` deltas
when a version appears in the name as well as in `DisplayVersion`. This is the
identity problem to solve, and it is more important than any schema question.

---

## The default scan: a derived allowlist

> **Superseded in part by measurement.** See
> [the derived allowlist does not hold up](#measured-the-derived-allowlist-does-not-hold-up)
> below: only about a quarter of installed products record an `InstallLocation`,
> so an allowlist derived from that field alone reaches roughly a quarter of the
> executables on a real machine. The reasoning here about *not* walking the
> whole drive stands; the conclusion that an allowlist can replace enumeration
> does not.

The default must **not** walk the whole drive.

Take `InstallLocation` from every registry entry, add `%ProgramFiles%`,
`%ProgramFiles(x86)%` and `%ProgramData%`, and scan exactly those with Syft.
The allowlist writes itself from what is actually installed, so it is neither a
guess nor a maintenance burden. `--scan-path` adds roots, `--exclude` subtracts
within them, matching the existing CLI shape.

This is fast, needs no elevation, and cannot wander into a mapped network drive.

### Measured: why this is necessary rather than merely tidy

This section originally argued for an allowlist from first principles. It has
since been measured, and the measurement is stronger than the argument.

The first execution of the cross-compiled binary on a real Windows 11 machine
scanned `C:\Program Files` and **did not finish**. Not slowly - a 5-minute
deadline elapsed with no result, twice, on a 20-core laptop. A goroutine dump
taken mid-scan named the cause exactly:

```
syscall.createFile(...)
os.Open(...)
syft/internal/fileresolver.NewMetadataFromPath  metadata.go:24
directoryIndexer.addFileToIndex                 directory_indexer.go:337
directoryIndexer.indexPath                      directory_indexer.go:281
path/filepath.Walk
```

Syft's directory indexer **opens every regular file in the tree**, before any
cataloger runs, in order to sniff its MIME type. On Linux that is cheap. On
Windows every `os.Open` is a `CreateFile` with `GENERIC_READ`, and Defender's
real-time protection scans a file when it is *opened*, not only when it is read.
`C:\Program Files` is tens of thousands of large executables, so the indexer
pays a full antivirus scan for each one.

Three things follow, and all three were confirmed on the machine:

- **Cataloger selection cannot avoid it.** `--catalogers os` selects nothing
  that can match on Windows and should have returned zero components in about a
  second. It stalled identically, because indexing happens first and is
  unaffected by which catalogers are selected.
- **This is not something swinv can fix from outside Syft.** The only lever
  available is scanning fewer paths - which is what the allowlist is.
- **`--full-scan` over a whole volume would be far worse.** If `Program Files`
  alone cannot complete in five minutes, walking `C:\` is not a slow option; it
  is not an option.

For comparison, swinv's own symlink pre-flight walks the same tree in **1.8
seconds**, because `filepath.WalkDir` only `Lstat`s and never opens anything.
The gap between 1.8 seconds and "did not finish" is the cost of the MIME sniff.

This also strengthens the case in [`--full-scan`](#--full-scan) for discovery
via the USN journal, which reads MFT records and opens nothing at all.

### A related defect this uncovered

The same run exposed something independent of Windows: a `--timeout 5m` scan was
still running at 5m30s. Syft's indexer walks with `filepath.Walk`, which takes
no context and checks no cancellation, so a scan wedged in indexing never
reaches a point where the deadline is consulted. `--timeout` was documented as a
whole-run deadline and was not one.

swinv now runs a watchdog that terminates the process if the scan outlives its
deadline by more than a short grace period. Exiting hard is not elegant, but a
deadline a caller cannot rely on is worse than no deadline, and atomic writes
mean termination can never leave a half-written report.

---

## `--full-scan`

Scanning every `.exe` and `.dll` on the system is a genuinely valuable thing to
be able to do. The software nobody installed through a package manager is
exactly the software nobody is tracking, which is the same argument that
justifies the loose-binary cataloger on Linux. In an air-gapped network where
nothing else inventories these hosts, it may be the most important thing the
tool finds.

It is opt-in because it is expensive, not because it is wrong.

### Discovery: the MFT, via `FSCTL_ENUM_USN_DATA`

Walking directories to find every PE on a Windows volume is slow, and on
Windows it is worse than slow: traversing **OneDrive cloud placeholders
hydrates them**, quietly downloading the user's entire cloud drive.

Instead, enumerate the NTFS Master File Table with the
`FSCTL_ENUM_USN_DATA` control code. This returns every file record on the
volume without opening a single file.

**Use the ioctl, not a raw MFT parser.** `FSCTL_ENUM_USN_DATA` is a documented
Win32 API - the OS parses the MFT for us. `DeviceIoControl` is already exposed
by `golang.org/x/sys/windows`, so this needs **no new dependency** and no
on-disk NTFS structure parsing to keep correct across Windows versions.
(`Velocidex/go-ntfs` is Apache-2.0 and licence-safe if raw access is ever
genuinely required, but it should not be for this.)

Two problems disappear:

- **Speed.** Reading file records instead of walking directory trees is the
  difference between seconds and minutes; it is how tools like Everything index
  a volume instantly.
- **Cloud hydration.** Metadata records are read, files are never opened, so
  placeholders stay dehydrated.

### Measured: the saving is larger than traversal alone

This section originally credited USN enumeration with removing the cost of
*walking* the tree, and treated the per-file cost as unavoidable. Running the
current binary on Windows showed that undersells it.

Syft's indexer opens **every regular file** in the tree and reads roughly 3 KB
of it, purely to determine a MIME type, before any cataloger runs. On a scan of
`/usr` on Linux that amounted to 5.9 GB read from a 4.8 GB tree - more than the
tree itself, because most files are opened twice. On Linux the page cache
absorbs this and it costs almost nothing. On Windows there is no equivalent
shortcut: every `CreateFile` traverses Defender's filter driver whether the
content is cached or not.

Enumerating through the USN journal returns every filename without opening
anything, so candidates can be filtered **by extension before a single handle
exists**. Most of a Program Files tree is not an executable - it is resources,
icons, localisation, documentation and data. Those files would never be opened
at all, rather than being opened, sniffed, and then discarded as uninteresting.

So the saving is not one cost but three: the directory traversal, the MIME sniff
on every non-candidate, and the antivirus interception that each of those opens
provokes.

### Measured: the first real enumeration

Implemented in `internal/usn` and run against a stock Windows 11 volume on a
hosted CI runner:

| | |
|---|---|
| MFT records read | **1,301,728** |
| elapsed | **42 s - 1 m 41 s** across runs |
| directories retained for path reconstruction | 199,644 |
| executables kept (`.exe .dll .sys .ocx .cpl .drv`) | 127,228 |
| paths that failed to reconstruct | **0** |
| **fraction of the volume kept** | **9.8%** |

The last row is the result that matters. A directory walk opens all 1.3 million
files; this opens none, and only 9.8% of them are even candidates for the file
reads that follow. The other 90.2% cost one MFT record each and are never
touched again.

For comparison, `C:\Program Files` alone - a fraction of that volume - did not
finish inside ten minutes through the directory resolver.

### Measured: a real, loaded machine

The CI figures come from a stock Windows 11 image with almost nothing installed.
The same probe on a working developer laptop -- NVIDIA, Qt, Anaconda, Visual
Studio, Office, Siemens tooling -- gives a very different and more useful
picture:

| | CI runner | real laptop |
|---|---|---|
| MFT records | 1,301,728 | **2,888,844** |
| elapsed | 42 s | **14.4 s** |
| directories | 199,644 | 510,205 |
| executables kept | 127,228 | 99,767 |
| paths unresolved | 0 | **0** |
| fraction kept | 9.8% | **3.5%** |

Twice the records in a third of the time, and 96.5% of the volume never opened.
The comparison that matters: `C:\Program Files` alone does not finish inside ten
minutes through the directory resolver; the *entire volume* enumerates in
fourteen seconds.

Where the candidates live is more instructive than the totals:

```
   39536  C:\Windows\WinSxS
   10703  C:\Program Files\WindowsApps
    6099  C:\Users\chris
    5922  C:\Program Files (x86)\Microsoft Visual Studio
    4718  C:\Program Files\dotnet
    3096  C:\Program Files\Siemens
    2081  C:\Qt\6.7.2
    1687  C:\Qt\Tools
    1438  C:\Windows\System32
    1415  C:\Program Files (x86)\Windows Kits
    1365  C:\Program Files\Microsoft Office
    1234  C:\ProgramData\anaconda3
```

Three conclusions, each of which changes a decision:

**WinSxS is 40% of all candidates.** It is the servicing component store:
hard-linked backing copies of files that also exist in their live locations. It
is not installed software in any sense an operator cares about, and excluding it
removes two-fifths of the extraction work before anything else is decided.

**Real software lives outside `%ProgramFiles%`.** `C:\Qt\6.7.2`, `C:\Qt\Tools`
and `C:\ProgramData\anaconda3` account for roughly five thousand candidates in
locations no fixed allowlist would guess. An allowlist has to be *derived* from
the registry's `InstallLocation` values, not hard-coded, and this is the
evidence for it.

**Per-user software is where the registry is weakest.** `C:\Users\chris` holds
six thousand candidates -- editors, runtimes, Electron applications, package
manager globals. Those are registered under `HKCU`, which means a scan running
as SYSTEM from a scheduled task, or as a different administrator, reads the
wrong hive; other users' hives are not loaded at all. The files are on disk
regardless of whose hive is mounted, so this is the clearest case where MFT
enumeration sees software the registry cannot.

That last point is the argument for building both. The registry is the source of
truth for machine-wide software and is nearly free to read. Enumeration is what
finds the rest.

### Measured: the derived allowlist does not hold up

This document proposed a **derived allowlist** as the default scan: take
`InstallLocation` from every uninstall key, scan those paths, and treat
`--full-scan` as the exception. That was reasoned, not measured. Measuring it
does not support it.

On the same real machine, comparing what MFT enumeration finds against what the
registry claims:

| | interactive | as SYSTEM |
|---|---|---|
| products in the uninstall keys | 380 | 353 |
| **of those, with an `InstallLocation`** | **106 (28%)** | **88 (25%)** |
| executables under a registry location | 23,600 | 17,997 |
| **coverage** | **23.7%** | **18.0%** |

The failure is upstream of path matching. **Roughly three quarters of installed
products record no install location at all**, so the allowlist has nothing to
derive from for most of what is installed. No amount of better matching fixes
that.

Two mitigations are worth measuring before concluding, and the probe now reports
both:

- `DisplayIcon` and `UninstallString` usually name a file *inside* the install
  directory, so the directory can be recovered from them when `InstallLocation`
  is absent. Cheap, and it needs no new API.
- The raw 76% miss overstates the gap, because much of it is software that
  should never come from an uninstall-key allowlist: everything under
  `\Windows` belongs to the component store and update inventory, and
  `WindowsApps` belongs to the Appx API. On this machine that is 39,536 +
  10,703 + 1,438 = over half the uncovered files. The honest denominator is
  third-party software, and the probe reports coverage both ways.

Even so, the conclusion the design has to absorb is that **MFT enumeration is
load-bearing rather than a fallback.** The registry remains the best source of
*identity* -- name, version, publisher -- and it is nearly free to read. It is
not a reliable source of *where the files are*.

### The architecture the measurements imply

Adding `DisplayIcon` and `UninstallString` as location sources raises the
products that yield a directory from 106 to **147**, and coverage of third-party
executables from 50.9% to **57.8%**:

| denominator | `InstallLocation` only | all three fields |
|---|---|---|
| all 99,919 executables | 23,600 (23.6%) | 27,303 (27.3%) |
| 46,366 third-party executables | 23,600 (50.9%) | **26,817 (57.8%)** |

Every file matched by `InstallLocation` is third-party - the two figures are
identical - which is expected: uninstall keys do not point into `\Windows`.

That still leaves 42% of third-party executables unreachable from the registry,
which looks like a poor result for an allowlist. It is, and the reason is that
**the allowlist was pointed the wrong way round.**

An allowlist was proposed as a way to decide *what to scan*. But enumeration is
not the expensive part - the whole volume enumerates in under five seconds and
opens nothing. The expensive part is **extraction**: opening a candidate binary
to read its `VERSIONINFO`, which is where antivirus interception is paid.

And a file that lies under a known product's install directory is exactly the
file whose version is **already known**, from the registry, for free. Opening it
to learn what the registry just said is wasted work.

So the registry coverage is not a scan filter. It is an **extraction filter**,
and it works in the opposite direction:

```
  enumerated executables            99,919   0 files opened, 4.7 s
  - OS / Store territory            53,553   component store + Appx API
  = third-party                     46,366
    - attributed to a known product 26,817   version already known
    = needs a file opened           19,549
```

**Extraction drops from 99,919 files to 19,549 - 80% fewer opens**, and 0.68% of
the volume. On the same assumption that a Defender-intercepted open costs
10-30 ms, that is the difference between roughly 17-50 minutes and roughly
3-10 minutes.

That number is an estimate, not a measurement: per-file extraction cost has not
been measured yet and is the next thing worth measuring.

The resulting shape, which is what the collector should be built to:

1. **Registry first.** 380 products with name, version and publisher, no file
   opened. This is the inventory, and it is the Windows analogue of reading
   `dpkg/status`.
2. **Enumerate the MFT.** Every executable on the volume in seconds, no file
   opened. This is discovery.
3. **Attribute.** Match enumerated paths against known products' directories.
   Attributed files need no extraction; they inherit the registry's version.
4. **Extract only the remainder.** The unattributed third-party files are the
   software nobody has an inventory record for -- Qt, Anaconda, per-user tools
   -- which is precisely the software worth finding.

Step 4 is what `--full-scan` should mean. Not "open everything", but "open the
part nothing else can account for".

### Measured: the first `--full-scan` is slow, and the rest are not

`--full-scan` on a real developer laptop - 2.9M MFT records, 99,920
executables, 19,549 of them opened after attribution - took **14 minutes 21
seconds** the first time and **1 second** the next. The same command, the same
counts, the same 14,769 components extracted.

Three runs isolate the cause:

| run | cache | priority | workers | extraction |
|---|---|---|---|---|
| 1 | cold | background | 5 | **861 s** |
| 2 | warm | normal (`--fast`) | 20 | 3 s |
| 3 | warm | background | 5 | **1 s** |

Runs 2 and 3 differ only in scheduling priority and worker count: 3 s against
1 s, which is noise. Runs 1 and 3 are identically configured and differ only in
cache warmth: 861 s against 1 s.

So neither `--fast` nor parallelism matters here. **Windows Defender's scan
cache accounts for essentially all of it.** The phase timings say the same
thing independently: MFT enumeration, which opens no files, stayed between 4.8
and 9.2 seconds across all three runs, while extraction, which opens 19,549,
fell by a factor of roughly 860. Whatever changed applies only to opening
files.

Two things follow.

**The background-priority default is right on Windows.** It was applied there by
analogy with Linux, where it was measured to cost 36% of runtime, and that
assumption was never checked. It has now been: the polite run was the fastest
of the three. `--fast` buys nothing for `--full-scan` and can be left alone.

**Operators should expect the first run to be slow and say so.** A daily
scheduled task pays the cold cost once and then runs in seconds, because most
executables do not change between runs. A fresh machine, or one that has just
taken a large Windows update, pays it again. Fourteen minutes followed by eight
seconds for the same command looks like a bug if nobody has written down that
it is not.

### Measured: the cost of running as SYSTEM

An unattended scan runs from a scheduled task as `NT AUTHORITY\SYSTEM`, which
reads `HKCU` for the SYSTEM account rather than for any real user. The size of
that blind spot, measured by running the same probe both ways on one machine:

- **27 fewer products** visible (380 → 353)
- **18 fewer install locations** (106 → 88)
- **5,603 fewer executables** attributable to a known product

Per-user software -- editors, language runtimes, Electron applications, package
manager globals -- is registered per user and is invisible to a service account.
`C:\Users\chris\AppData\Local\uv` alone holds 1,300 executables.

The files are on disk regardless of which hive is loaded, so enumeration sees
them and the registry does not. If per-user software matters to an operator,
either the scan runs interactively, or unloaded user hives get mounted and read
-- which is considerably more invasive and needs its own decision.

### Hard links: a file appears under one path, not all of them

The MFT holds one record per *file*, not per *name*, and `FSCTL_ENUM_USN_DATA`
reports a single name and parent per record. A file with several hard links
therefore surfaces under exactly one of its paths.

This is not a corner case on Windows. Component servicing hard-links from the
WinSxS store into live locations, so on the test volume
`C:\Windows\System32\kernel32.dll` was reported as

```
C:\Windows\WinSxS\amd64_microsoft-windows-kernel32_31bf3856ad364e35_10.0.26100.33158_none_...\kernel32.dll
```

and the `System32` path did not appear at all.

Nothing is missed - the file is enumerated, once - but its reported location may
not be the one an operator recognises, and a consumer asking "is there something
at `C:\Windows\System32\X`" will get the wrong answer. Two consequences:

- Reporting a component's location from MFT enumeration alone is
  under-specified. Where the path matters, it needs corroborating from the
  registry's `InstallLocation` or by resolving links explicitly.
- It is another argument against MFT enumeration as the *primary* source. It is
  a discovery mechanism for software the registry does not know about, which is
  what `--full-scan` is for. The registry remains the source of truth.

Resolving every name would mean opening each file and calling
`FindFirstFileNameW`, which reintroduces exactly the per-file open this exists
to avoid. Not worth it by default; possibly worth it for a narrow set of paths.

### Volume selection replaces the default, it does not extend it

`--volumes D:` scans D: and **does not scan C:**. `--volumes D:,E:` scans both
and, again, not C:. An operator who names volumes has said which ones they want,
and silently adding the system drive would produce a far longer scan than they
asked for - on the machine where they were most likely trying to avoid one.

Duplicates are dropped in first-mentioned order, so a volume is never enumerated
twice and the output is deterministic. An unset flag means "use the default",
which is distinct from naming no volumes at all.

Each volume is checked for NTFS independently, so an NTFS `C:` alongside a ReFS
`D:` behaves as described in [Behaviour on a non-NTFS filesystem](#behaviour-on-a-non-ntfs-filesystem)
rather than failing the whole run.

### Implementation note: file references carry a sequence number

Recorded because it cost a full CI cycle and failed silently. An NTFS file
reference is not a record index: the low 48 bits are the MFT record number and
the high 16 are a sequence number, incremented whenever a record is reused. The
root directory's reference is `0x0005000000000005`, not `5`.

Code that compares or keys on the full reference finds nothing, reports every
entry as unresolved, and raises no error - because unresolved entries are a
legitimate outcome on a live filesystem, just not 100% of them. Every identity
comparison must mask to the low 48 bits first.

Unit tests written with invented reference numbers pass against this bug,
because they encode the same wrong model. The tests now construct references the
way NTFS does.

### What this does *not* solve

**MFT enumeration gives discovery, not extraction.** Every candidate PE still
has to be opened and its `VERSIONINFO` resource parsed to get a product and
version. On a typical Windows install that is 50,000-100,000 files.

The bottleneck moves; it does not vanish. Discovery drops from minutes to
seconds, extraction remains minutes. `--full-scan` is a minutes-scale
operation and should be described as one.

### Attribution, so the output is not half duplicates

On Linux, dpkg and rpm ship file manifests, which is what lets Syft's
`ExcludeBinaryPackagesWithFileOwnershipOverlap` stop a package's own binaries
being reported a second time as loose binaries. Registry entries have no file
list, so that mechanism does not exist on Windows - and without a replacement,
every installed product's `.exe` would appear twice.

Two sources reconstruct most of it:

1. **MSI components.** `MsiEnumComponents` with `MsiGetComponentPath` maps
   components to products - the precise equivalent of a dpkg `.list`, for every
   MSI-installed product.
2. **`InstallLocation` prefix matching** for everything else. A PE under a
   product's `InstallLocation` belongs to that product.

What remains unattributed after both - portable applications, stray DLLs,
things dropped into a directory by hand - is **exactly what the full scan
exists to surface**, and should be reported as unmanaged rather than discarded.

> This is the piece to prototype first. If attribution does not hold,
> `--full-scan` produces mostly duplicate noise and is worth much less.

### Behaviour on a non-NTFS filesystem

ReFS has no MFT. FAT32 and exFAT have nothing comparable. On those volumes
`--full-scan` has no fast path and falls back to walking every directory, which
is the slow behaviour the flag exists to avoid.

**`--full-scan` therefore refuses to run on a non-NTFS volume unless the
operator explicitly accepts the fallback.**

```console
$ swinv --full-scan --out C:\inv
swinv: --full-scan is not recommended on this filesystem.
       D:\ is ReFS, which has no Master File Table, so the scan would fall back
       to walking every directory. That is substantially slower and, on volumes
       holding cloud-backed files, may cause placeholders to be downloaded.
       Re-run with --accept-slow-scan to proceed anyway.
```

Exit code **2**, a usage error, consistent with every other refusal.

With `--accept-slow-scan` the scan proceeds by directory traversal and records
a warning in `scan.warnings` naming each volume that took the slow path, so the
choice is visible in the report and not only in the operator's shell history.

The check is per volume. A machine with NTFS on `C:` and ReFS on `D:` is the
normal case, not an edge case: `C:` takes the fast path and only `D:` triggers
the refusal. Skipping the ReFS volume entirely, with `--exclude`, is a third
valid answer and the message should not imply the only options are "accept" or
"give up".

### Elevation

A raw volume handle requires Administrator. Without it there is no MFT access
at all.

Unelevated, `--full-scan` falls back to directory traversal and says so in
`scan.warnings`. It does **not** refuse: running unprivileged is a supported
mode on Linux and must stay one here. `ran_as_root` becomes a token-elevation
check rather than `Geteuid() == 0`.

---

## Host facts

| `model.Host` field | Windows source |
|---|---|
| `hostname` | `GetComputerNameEx` |
| `machine_id` | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` - the stable fleet key |
| `os_id` | `"windows"` |
| `os_version_id` | `DisplayVersion` (or `ReleaseId` on older builds) under `Windows NT\CurrentVersion` |
| `os_pretty_name` | `ProductName` from the same key |
| `kernel_release` | `CurrentBuildNumber` + `UBR`, e.g. `19045.4780` |
| `architecture` | `runtime.GOARCH`, unchanged |
| `system_vendor`, `product_name` | `Win32_ComputerSystem` / `Win32_ComputerSystemProduct` |
| `virtualization` | `Win32_ComputerSystem.Model` heuristics, as the DMI heuristics work today |
| `boot_id` | no equivalent; leave empty rather than inventing one |

WMI is acceptable *here* - for read-only hardware and OS facts. The objection
to `Win32_Product` is specific to that class, not to WMI generally.

---

## Schema

**Same `schema_version`, same CSV columns, new `type` values.** The cross-platform
join is worth more than perfect Windows fidelity, and new types cost nothing:
`windows` for ARP entries, `msix`, `hotfix`. `dotnet` and `binary` already exist
and keep their meaning.

**Components carry candidate CPEs.** This was missing from the original design,
which discussed PURL and never mentioned CPE. The consequence was worse than the
omission looks: with no PURL *and* no CPE a component has no identifier at all,
so a CycloneDX document from a Windows host matches nothing in any vulnerability
scanner - and returns a clean-looking empty result rather than an error.

CPE is the right identifier here. It exists for exactly this case: commercial
and proprietary software with no package manager behind it, identified by vendor
and product. Several candidate forms are emitted per component rather than one,
because publisher and product strings in the registry are written by thousands of
unrelated installers and rarely match the NVD's spelling - "Google LLC" against
`google`, "Google Chrome" against `chrome`. The failure mode is a miss rather
than a false match, since a CPE only matches when vendor and product both hit.

**`purl` stays empty for registry entries.** There is no canonical PURL type for
an ARP row, and inventing `pkg:generic/windows/...` would create false
confidence - a scanner would silently match nothing against it rather than
reporting that it could not. Syft-derived PE and .NET components keep their real
PURLs. Windows consumers join on `(name, type, version)`, which is what
`ComputeDelta` already does.

Windows-specific identity - `product_code`, `upgrade_code`,
`package_family_name`, `install_scope`, the originating registry key - is worth
keeping but does not belong in the fixed CSV columns. Adding a general
`attributes` map to `Component` is the smaller change, and it would serve Linux
too.

---

## Exclusion model

There is no `/proc/self/mountinfo`. The equivalent is volume enumeration:

- Skip `DRIVE_REMOTE` (mapped network drives), `DRIVE_CDROM` and
  `DRIVE_REMOVABLE` by default. Mapped drives are the Windows equivalent of the
  NFS mount that made a Linux scan take hours.
- Skip **cloud-placeholder reparse points**. Under `--full-scan` the MFT path
  avoids hydration for free; under directory traversal it must be explicit.
- Do not follow junctions across volumes. Windows junctions create cycles and
  cross-volume jumps exactly as symlinks do on Linux, and the symlink preflight
  lesson applies unchanged.
- Default subtree exclusions: `$Recycle.Bin`, `System Volume Information`,
  `Windows\WinSxS`, `Windows\Installer`.

---

## Running air-gapped

The default posture already fits. Worth stating explicitly:

- No source of installed software requires the network. winget is excluded
  partly for this reason.
- `--offline` remains available and, on Windows, there is no FQDN lookup to
  suppress in the first place unless one is added.
- For the CycloneDX handoff, `grype` needs a **pre-staged vulnerability
  database** (`grype db import`) rather than its auto-update. That is a
  documentation matter for the consuming side, not a change here.

---

## Phasing

| Phase | Scope | Rough effort |
|---|---|---|
| 1 | hostfacts, ARP from four hives, Syft on derived install roots | 2-3 weeks |
| 2 | MSI products and patches, Appx/MSIX, CBS hotfixes, attribution | 3-4 weeks |
| 3 | `--full-scan` via `FSCTL_ENUM_USN_DATA`, volume policy, `--accept-slow-scan` | 2-3 weeks |
| 4 | Scheduled-task packaging, MSI or winget manifest, Windows CI | 1-2 weeks |

Phase 1 alone ships something real and answers the question that matters: does
the model hold on Windows at all? Everything after it is worth more once that
is known.

**Estimates are reasoned, not measured.** Nobody has written any of this.

## The condition

**If a Windows CI runner and a real Windows 10 machine for validation are not
available, do not start.** GitHub Actions provides `windows-latest` free, so CI
is not the obstacle; a real machine is.

The evidence for this is the Linux work. Every significant defect in this
project - a 9p mount contributing 48% of a bogus inventory, phantom packages
from a nested root filesystem, Gentoo's quoted `os_id`, a documented container
command that hung - was found by running the tool on hardware the author did
not have, and none were found by 110 tests, a three-model review panel, or five
automated review passes. Windows inventory is substantially more edge cases than
Linux, and a Windows binary that reports subtly wrong installed software is
worse than no Windows support.

## Rejected alternatives

| Rejected | Why |
|---|---|
| `Win32_Product` | Triggers MSI consistency checks; can repair and mutate the machine; MSI-only |
| Walking `C:\` by default | Slow, hydrates cloud placeholders, and without ownership data produces mostly duplicates |
| Operator-supplied allowlist as the primary model | The registry already knows where things are installed; deriving it is more accurate and needs no maintenance |
| A separate Windows project | Forks `model`, the writers and the delta logic - the parts most worth sharing |
| `pkg:generic/windows/...` PURLs | False confidence: matches nothing, but looks like it should |
| Raw MFT parsing | `FSCTL_ENUM_USN_DATA` does it through a documented API with no dependency and no on-disk format risk |
| winget as a source | Re-reads ARP and Appx, and expects network access |

## Language ecosystems: two of forty

**Implemented for Python and npm.** Under `--full-scan`, packages installed by
`pip` and `npm` are read from their manifests.

The Windows collector does not use Syft, so the roughly forty ecosystems the
Linux collector covers are not available to it. Cargo, Maven, RubyGems,
Composer, NuGet and the rest remain uncovered.

This matters more than the component count suggests. Language packages are where
most third-party vulnerabilities are, they are installed outside any package
manager Windows knows about, and they are exactly the class the uninstall
registry cannot see - which is the gap `--full-scan` exists to close for native
code and does not close here.

### The shape a fix should take

Not "run Syft over C:\". That is the strategy already measured as unworkable,
for the same reason as before: Syft's indexer opens every file it sees.

MFT enumeration already produces every filename on the volume without opening
anything. Ecosystem manifests are identifiable **by name** - `METADATA` inside a
`*.dist-info` directory, `PKG-INFO` inside `*.egg-info`, `package.json`,
`go.mod`, `Cargo.lock`, `*.gemspec` - so the same enumeration that finds
executables can find manifests, and only those files need opening. The
extraction filter that cut 99,920 candidates to 19,549 applies unchanged.

The manifests are parsed directly rather than handed to Syft as narrow roots.
Handing Syft a `node_modules` tree reintroduces its indexer over every file in
it; parsing the manifests opens exactly the files enumeration already named and
nothing else. The cost is reimplementing two catalogers, which for two
ecosystems is a smaller price than the indexer.

A manifest that parses but describes no installed package is skipped quietly.
Most `package.json` files under a project tree are configuration rather than an
installed dependency, and a warning apiece would drown the ones that matter.

Note one thing this would gain that Linux has and Windows would not: on Linux,
`owned_by` links a distribution-installed language package to the OS package
that patches it. Nothing on Windows installs Python packages through a system
package manager, so every ecosystem package found there is genuinely upstream
and should be assessed as such - which makes the absent link correct rather
than missing.

## Open questions

1. **Does MSI component attribution actually hold?** The whole value of
   `--full-scan` depends on it. Prototype first.
2. **How should `DisplayName` be normalised** when it embeds the version and
   varies by locale? This is the identity problem, and it affects `--since`
   more than anything else.
3. **Should `SystemComponent=1` entries be reported by default?** They are real
   software but hidden from Add/Remove Programs, and including them will make
   Windows counts look inflated next to what an operator sees in the UI.
4. **Server-role detection** - deducing that IIS is serving, and which product
   and version sits behind a listening port - is a different axis from "what is
   installed" and is not designed here. It now has its own document:
   [Server-role detection](SERVER-ROLES.md). Note one finding from it that bears
   on this document: IIS does not fit a socket → process → binary pipeline at
   all, because `HTTP.sys` owns the socket in kernel mode. IIS topology has to
   come from `applicationHost.config`, which is read offline and suits an
   air-gapped scan better than anything runtime-derived.

---

## Appendix: the baseline measurement protocol

The tree cross-compiles for Windows today and produces a `swinv.exe` that has
never been executed. Running it is not a test of Windows support - there is no
Windows support - it is the measurement that decides how much of this document
survives contact with a real machine. Three numbers come out of it, and each one
moves a decision:

| What you measure | What it decides |
| --- | --- |
| How many installed products Syft's PE cataloger finds, against the uninstall registry | Whether the registry collector is the whole job or merely most of it |
| How long a scoped scan of `Program Files` takes | Whether the derived-allowlist default is necessary or merely tidy |
| Whether the writers survive an NTFS round trip | Whether Phase 1 is days or weeks |

CI publishes the binary as the `swinv-windows-amd64-experimental` artifact on
every push to `main`. Download it from the run page under **Actions**, unzip it,
and keep it out of `PATH` - it is an instrument, not an install.

### Before the first run

Three things about this binary on Windows are worth knowing before it touches a
disk, because none of them are obvious from the Linux behaviour.

**Do not point it at `C:\`.** The exclusion model keys on `etc/os-release` to
decide whether a `--root` is a whole filesystem deserving the layout exclusions.
`C:\` has no such file, so it is treated as an arbitrary directory and gets *no
exclusions at all* - not the mount table, not the non-local filesystem list, not
the home-directory rule. The scan walks `System Volume Information`, `WinSxS`,
every user profile, and the page file.

**Especially do not point it at `C:\` on a machine with OneDrive, or any other
cloud-sync client.** Files-On-Demand placeholders are reparse points that
materialise their contents when opened, so a naive directory walk quietly
downloads the entire cloud drive. On a metered connection or a large tenant this
is a genuinely expensive mistake, and it is the single strongest argument in
this document for the USN-journal approach, which never opens a file.

**Run as an ordinary user first.** An unprivileged run tells you what the
tool can see without help, which is what an air-gapped operator without local
admin will actually get. Elevate only for the step that asks for it.

Use a throwaway output directory throughout:

```powershell
mkdir C:\swinv-test
```

### T0 - does it start

```powershell
.\swinv.exe --version
.\swinv.exe --help
```

Expected: both work. The flag parser, the version stamp and the help text are
platform-neutral. If `--help` is empty or the binary refuses to start, stop and
report it - nothing else in this protocol is meaningful.

### T1 - the first real scan

```powershell
Measure-Command { .\swinv.exe --root "C:\Program Files" --out C:\swinv-test --output-mode timestamped --offline }
```

`--offline` matters here beyond its usual meaning: it suppresses the FQDN
lookup, which on a domain-joined machine can block for seconds against a DNS
server that is not there.

Record the elapsed time and whether a file appeared. **A file appearing at all
is itself a result** - it exercises the atomic write path end to end on NTFS,
which is temp file, `fsync`, `MoveFileEx`, and, as of this change, no directory
flush. If nothing was written and the error mentions syncing a directory, the
Windows build-tag split did not take effect and that is the finding.

### T2 - what it thinks the host is

```powershell
$r = Get-Content (Get-ChildItem C:\swinv-test\*.json | Select -Last 1) | ConvertFrom-Json
$r.host | Format-List
$r.scan.warnings
```

Expect most of `host` to be empty: `os_id`, `os_version_id`, `kernel_release`,
`machine_id` and `boot_id` all come from files under `/etc` and `/proc`.
`hostname` and `architecture` should survive, since they come from the Go
runtime rather than the filesystem.

The question worth answering is not *whether* it degrades - it must - but
*how*: does it degrade quietly into empty strings, or does it announce itself in
`scan.warnings`? A report that claims a Windows host with a blank `os_id` and
says nothing about it is a correctness bug in the existing code, not a missing
feature, and it would be worth fixing before any Windows work starts.

### T3 - what the catalogers actually found

```powershell
$r.components.Count
$r.components | Group-Object found_by | Sort-Object Count -Descending | Format-Table Count, Name
$r.components | Group-Object type      | Sort-Object Count -Descending | Format-Table Count, Name
$r.components | Where-Object { $_.type -eq 'dotnet' } | Select -First 10 name, version, purl
```

This is the load-bearing measurement. Syft has `binary-classifier`, `dotnet-deps`
and `dotnet-portable-executable` catalogers, and the design assumes they produce
real version data from PE `VERSIONINFO` and `.deps.json`. Confirm it, and check
whether the versions look like file versions or product versions - they differ
often enough to matter for CVE matching.

### T4 - the gap against installed-software truth

This is the number that justifies the registry collector. Take the uninstall
registry as ground truth:

```powershell
$arp = Get-ItemProperty @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
  ) -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation

$arp.Count
(Get-AppxPackage).Count      # Store / MSIX, invisible to the uninstall keys
(Get-HotFix).Count           # updates, a separate inventory again
```

> **Never run `Get-WmiObject Win32_Product` or `Get-CimInstance Win32_Product`.**
> Enumerating that class triggers an MSI consistency check against every
> installed product, which can silently reconfigure or repair software on the
> machine. It is the obvious thing to reach for and it is the one query in this
> protocol that can change the system it is measuring. `Get-HotFix` is safe - it
> reads `Win32_QuickFixEngineering`, which has no such behaviour.

Then compare, roughly, by hand:

```powershell
# products the registry knows about that swinv found nothing resembling
$found = $r.components.name
$arp | Where-Object { $n = $_.DisplayName; -not ($found | Where-Object { $n -like "*$_*" -or $_ -like "*$n*" }) } |
  Select-Object DisplayName, DisplayVersion | Format-Table
```

The match will be fuzzy and that is fine - the output is an order of magnitude,
not a percentage. If Syft alone accounts for most of the ARP list, the registry
collector is an enrichment. If it accounts for a fraction, the registry
collector *is* the product and the file scan is secondary. Everything in the
phasing table above assumes the second, on reasoning rather than evidence; this
is where that assumption gets checked.

### T5 - the cost of breadth

```powershell
Measure-Command { .\swinv.exe --root "C:\Program Files (x86)" --out C:\swinv-test --output-mode timestamped --offline }
Measure-Command { .\swinv.exe --root "C:\Windows\System32"    --out C:\swinv-test --output-mode timestamped --offline }
```

`System32` is the interesting one. It is large, it is almost entirely OS
components already accounted for by the update inventory, and it is the clearest
test of whether including it by default would drown the report. Run it last:
if it takes long enough to be annoying, that is the answer.

Do **not** attempt `C:\Windows\WinSxS`. It is a hard-link farm with hundreds of
thousands of entries and no exclusion model is in place to survive it.

### T6 - durability, if you want to be thorough

```powershell
.\swinv.exe --root "C:\Program Files" --out C:\swinv-test --output-mode overwrite --offline
.\swinv.exe --root "C:\Program Files" --out C:\swinv-test --output-mode overwrite --offline
Get-ChildItem C:\swinv-test
```

`overwrite` mode must replace one file in place and leave no `.tmp-*` debris. A
stray temp file means the rename path is behaving differently on NTFS than the
tests on Linux assume.

### What to send back

The three numbers from T1, T3 and T4, the `scan.warnings` array from T2, and one
`.json` file. That is enough to either confirm the phasing in this document or
rewrite it. Nothing in this protocol validates Windows support, and a clean run
should not be reported as though it did - the tool is finding files on an
operating system whose notion of installed software it does not yet model.
