# Windows support — design

> **Status: proposed. None of this is implemented.**
>
> Every other document in `docs/` describes behaviour that ships and has been
> run. This one does not. It is a design to be argued with, and the estimates
> in it are reasoned rather than measured — nobody has run `swinv` on Windows
> yet.

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
assumes a server. `swinv`'s model — one static binary, no daemon, no network,
writes files that something else collects later — is exactly what an isolated
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
That is the long pole — not Go portability, not packaging.

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
| MSI products and patches | `msi.dll` — `MsiEnumProducts`, `MsiEnumPatches`, `MsiGetProductInfo` | MSI products, and patches, which do **not** appear under the uninstall keys |
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

The default must **not** walk the whole drive.

Take `InstallLocation` from every registry entry, add `%ProgramFiles%`,
`%ProgramFiles(x86)%` and `%ProgramData%`, and scan exactly those with Syft.
The allowlist writes itself from what is actually installed, so it is neither a
guess nor a maintenance burden. `--scan-path` adds roots, `--exclude` subtracts
within them, matching the existing CLI shape.

This is fast, needs no elevation, and cannot wander into a mapped network drive.

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
Win32 API — the OS parses the MFT for us. `DeviceIoControl` is already exposed
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

### What this does *not* solve

**MFT enumeration gives discovery, not extraction.** Every candidate PE still
has to be opened and its `VERSIONINFO` resource parsed to get a product and
version. On a typical Windows install that is 50,000–100,000 files.

The bottleneck moves; it does not vanish. Discovery drops from minutes to
seconds, extraction remains minutes. `--full-scan` is a minutes-scale
operation and should be described as one.

### Attribution, so the output is not half duplicates

On Linux, dpkg and rpm ship file manifests, which is what lets Syft's
`ExcludeBinaryPackagesWithFileOwnershipOverlap` stop a package's own binaries
being reported a second time as loose binaries. Registry entries have no file
list, so that mechanism does not exist on Windows — and without a replacement,
every installed product's `.exe` would appear twice.

Two sources reconstruct most of it:

1. **MSI components.** `MsiEnumComponents` with `MsiGetComponentPath` maps
   components to products — the precise equivalent of a dpkg `.list`, for every
   MSI-installed product.
2. **`InstallLocation` prefix matching** for everything else. A PE under a
   product's `InstallLocation` belongs to that product.

What remains unattributed after both — portable applications, stray DLLs,
things dropped into a directory by hand — is **exactly what the full scan
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
| `machine_id` | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` — the stable fleet key |
| `os_id` | `"windows"` |
| `os_version_id` | `DisplayVersion` (or `ReleaseId` on older builds) under `Windows NT\CurrentVersion` |
| `os_pretty_name` | `ProductName` from the same key |
| `kernel_release` | `CurrentBuildNumber` + `UBR`, e.g. `19045.4780` |
| `architecture` | `runtime.GOARCH`, unchanged |
| `system_vendor`, `product_name` | `Win32_ComputerSystem` / `Win32_ComputerSystemProduct` |
| `virtualization` | `Win32_ComputerSystem.Model` heuristics, as the DMI heuristics work today |
| `boot_id` | no equivalent; leave empty rather than inventing one |

WMI is acceptable *here* — for read-only hardware and OS facts. The objection
to `Win32_Product` is specific to that class, not to WMI generally.

---

## Schema

**Same `schema_version`, same CSV columns, new `type` values.** The cross-platform
join is worth more than perfect Windows fidelity, and new types cost nothing:
`windows` for ARP entries, `msix`, `hotfix`. `dotnet` and `binary` already exist
and keep their meaning.

**`purl` stays empty for registry entries.** There is no canonical PURL type for
an ARP row, and inventing `pkg:generic/windows/...` would create false
confidence — a scanner would silently match nothing against it rather than
reporting that it could not. Syft-derived PE and .NET components keep their real
PURLs. Windows consumers join on `(name, type, version)`, which is what
`ComputeDelta` already does.

Windows-specific identity — `product_code`, `upgrade_code`,
`package_family_name`, `install_scope`, the originating registry key — is worth
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
| 1 | hostfacts, ARP from four hives, Syft on derived install roots | 2–3 weeks |
| 2 | MSI products and patches, Appx/MSIX, CBS hotfixes, attribution | 3–4 weeks |
| 3 | `--full-scan` via `FSCTL_ENUM_USN_DATA`, volume policy, `--accept-slow-scan` | 2–3 weeks |
| 4 | Scheduled-task packaging, MSI or winget manifest, Windows CI | 1–2 weeks |

Phase 1 alone ships something real and answers the question that matters: does
the model hold on Windows at all? Everything after it is worth more once that
is known.

**Estimates are reasoned, not measured.** Nobody has written any of this.

## The condition

**If a Windows CI runner and a real Windows 10 machine for validation are not
available, do not start.** GitHub Actions provides `windows-latest` free, so CI
is not the obstacle; a real machine is.

The evidence for this is the Linux work. Every significant defect in this
project — a 9p mount contributing 48% of a bogus inventory, phantom packages
from a nested root filesystem, Gentoo's quoted `os_id`, a documented container
command that hung — was found by running the tool on hardware the author did
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
| A separate Windows project | Forks `model`, the writers and the delta logic — the parts most worth sharing |
| `pkg:generic/windows/...` PURLs | False confidence: matches nothing, but looks like it should |
| Raw MFT parsing | `FSCTL_ENUM_USN_DATA` does it through a documented API with no dependency and no on-disk format risk |
| winget as a source | Re-reads ARP and Appx, and expects network access |

## Open questions

1. **Does MSI component attribution actually hold?** The whole value of
   `--full-scan` depends on it. Prototype first.
2. **How should `DisplayName` be normalised** when it embeds the version and
   varies by locale? This is the identity problem, and it affects `--since`
   more than anything else.
3. **Should `SystemComponent=1` entries be reported by default?** They are real
   software but hidden from Add/Remove Programs, and including them will make
   Windows counts look inflated next to what an operator sees in the UI.
4. **Server-role detection** — deducing that IIS is serving, and which product
   and version sits behind a listening port — is a different axis from "what is
   installed" and is not designed here. It deserves its own document, and is
   arguably worth building on Linux first, where the package file-ownership
   graph makes the socket → process → binary → product join reliable.

---

## Appendix: the baseline measurement protocol

The tree cross-compiles for Windows today and produces a `swinv.exe` that has
never been executed. Running it is not a test of Windows support — there is no
Windows support — it is the measurement that decides how much of this document
survives contact with a real machine. Three numbers come out of it, and each one
moves a decision:

| What you measure | What it decides |
| --- | --- |
| How many installed products Syft's PE cataloger finds, against the uninstall registry | Whether the registry collector is the whole job or merely most of it |
| How long a scoped scan of `Program Files` takes | Whether the derived-allowlist default is necessary or merely tidy |
| Whether the writers survive an NTFS round trip | Whether Phase 1 is days or weeks |

CI publishes the binary as the `swinv-windows-amd64-experimental` artifact on
every push to `main`. Download it from the run page under **Actions**, unzip it,
and keep it out of `PATH` — it is an instrument, not an install.

### Before the first run

Three things about this binary on Windows are worth knowing before it touches a
disk, because none of them are obvious from the Linux behaviour.

**Do not point it at `C:\`.** The exclusion model keys on `etc/os-release` to
decide whether a `--root` is a whole filesystem deserving the layout exclusions.
`C:\` has no such file, so it is treated as an arbitrary directory and gets *no
exclusions at all* — not the mount table, not the non-local filesystem list, not
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

### T0 — does it start

```powershell
.\swinv.exe --version
.\swinv.exe --help
```

Expected: both work. The flag parser, the version stamp and the help text are
platform-neutral. If `--help` is empty or the binary refuses to start, stop and
report it — nothing else in this protocol is meaningful.

### T1 — the first real scan

```powershell
Measure-Command { .\swinv.exe --root "C:\Program Files" --out C:\swinv-test --output-mode timestamped --offline }
```

`--offline` matters here beyond its usual meaning: it suppresses the FQDN
lookup, which on a domain-joined machine can block for seconds against a DNS
server that is not there.

Record the elapsed time and whether a file appeared. **A file appearing at all
is itself a result** — it exercises the atomic write path end to end on NTFS,
which is temp file, `fsync`, `MoveFileEx`, and, as of this change, no directory
flush. If nothing was written and the error mentions syncing a directory, the
Windows build-tag split did not take effect and that is the finding.

### T2 — what it thinks the host is

```powershell
$r = Get-Content (Get-ChildItem C:\swinv-test\*.json | Select -Last 1) | ConvertFrom-Json
$r.host | Format-List
$r.scan.warnings
```

Expect most of `host` to be empty: `os_id`, `os_version_id`, `kernel_release`,
`machine_id` and `boot_id` all come from files under `/etc` and `/proc`.
`hostname` and `architecture` should survive, since they come from the Go
runtime rather than the filesystem.

The question worth answering is not *whether* it degrades — it must — but
*how*: does it degrade quietly into empty strings, or does it announce itself in
`scan.warnings`? A report that claims a Windows host with a blank `os_id` and
says nothing about it is a correctness bug in the existing code, not a missing
feature, and it would be worth fixing before any Windows work starts.

### T3 — what the catalogers actually found

```powershell
$r.components.Count
$r.components | Group-Object found_by | Sort-Object Count -Descending | Format-Table Count, Name
$r.components | Group-Object type      | Sort-Object Count -Descending | Format-Table Count, Name
$r.components | Where-Object { $_.type -eq 'dotnet' } | Select -First 10 name, version, purl
```

This is the load-bearing measurement. Syft has `binary-classifier`, `dotnet-deps`
and `dotnet-portable-executable` catalogers, and the design assumes they produce
real version data from PE `VERSIONINFO` and `.deps.json`. Confirm it, and check
whether the versions look like file versions or product versions — they differ
often enough to matter for CVE matching.

### T4 — the gap against installed-software truth

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
> protocol that can change the system it is measuring. `Get-HotFix` is safe — it
> reads `Win32_QuickFixEngineering`, which has no such behaviour.

Then compare, roughly, by hand:

```powershell
# products the registry knows about that swinv found nothing resembling
$found = $r.components.name
$arp | Where-Object { $n = $_.DisplayName; -not ($found | Where-Object { $n -like "*$_*" -or $_ -like "*$n*" }) } |
  Select-Object DisplayName, DisplayVersion | Format-Table
```

The match will be fuzzy and that is fine — the output is an order of magnitude,
not a percentage. If Syft alone accounts for most of the ARP list, the registry
collector is an enrichment. If it accounts for a fraction, the registry
collector *is* the product and the file scan is secondary. Everything in the
phasing table above assumes the second, on reasoning rather than evidence; this
is where that assumption gets checked.

### T5 — the cost of breadth

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

### T6 — durability, if you want to be thorough

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
should not be reported as though it did — the tool is finding files on an
operating system whose notion of installed software it does not yet model.
