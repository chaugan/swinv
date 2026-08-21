# Performance and tuning

How `swinv` spends time and memory, which knobs actually move the needle, and
how to measure the answer on your own host.

Part of the [swinv](../README.md) documentation.

---

## Read this before you read the numbers

Every measurement below comes from **one machine**, and that machine is not a
server:

| Property | Value |
|---|---|
| OS | Ubuntu 26.04 |
| Cores | 8 |
| Storage | SSD |
| Files under `/` | ~1,000,000 |
| Privilege | unprivileged (non-root) |

The file count is the part that matters. This host carries a developer checkout
in `/opt` — **156k files**, `node_modules` trees and all — on top of the usual
`/usr` (**118k**) and `/var` (**227k**). A fleet server with ~2000 dpkg packages,
no source trees and no vendored JavaScript is a completely different shape of
filesystem, and the numbers here do not transfer to it.

So treat this document as **measured behaviour of a walk-dominated workload**,
not as a spec sheet. The one number that generalises is the *shape* of the cost:
`swinv` is dominated by Syft's full-tree index, and the levers that work are the
ones that shrink the tree or bound the heap. Re-measure on your own hardware
before concluding anything (see [Measuring it yourself](#measuring-it-yourself)).

## Where the time and memory actually go

Syft builds a directory resolver by indexing **every path under the scan root**
before it parses anything. That index lives in memory for the duration of the
run. Peak RSS is therefore a function of how many paths were walked, not of how
many packages were found, and not of anything in `swinv`'s own conversion code.

Two consequences follow, and they explain most of what is surprising below:

1. Anything that narrows *parsing* (`--catalogers`) does not narrow the *walk*,
   so it saves far less than it looks like it should.
2. Anything that narrows the *walk* (`--exclude`, the default exclusions, the
   mount-table skipping) saves on both axes at once.

Micro-optimising the conversion path would be a waste of effort.

## Measured configurations

Wall time and peak RSS, measured with `/usr/bin/time -v` on the host described
above. **Every row produced the same inventory: 14,190 components.** These are
not different scans of different scope — they are the same work, tuned.

| Configuration | Wall | Peak RSS |
|---|---|---|
| default | 348 s | 2271 MB |
| `--no-file-ownership` | 233 s | 2414 MB |
| `--parallelism 2` | 322 s | 2197 MB |
| `--parallelism 1 --no-file-ownership` | 325 s | 1735 MB |
| **`--max-memory 1536MiB`** | **304 s** | **1580 MB** |
| `--max-memory 768MiB` | 546 s | 1337 MB |
| `--max-memory 768MiB --parallelism 1` | 615 s | 1085 MB |

Note that the slowest row here (615 s) still finishes comfortably inside the
default `--timeout 30m`. On a substantially larger host, or with `--hash` on
top, check that assumption rather than inheriting it.

## Three findings that are the opposite of what you would guess

### 1. `--catalogers os` does not make the scan cheap

The obvious way to get a fast OS-package-only inventory is to ask for only the
OS catalogers. It does not work, because **Syft indexes the whole filesystem
when it builds the directory resolver, before cataloger selection is applied**.
Narrowing catalogers narrows parsing; the walk is unchanged, and the walk is the
cost.

Measured: **135 s** for `--catalogers os`, against 348 s for the full default
scan — for an inventory of 1,566 components instead of 14,190, at ~1.1 GB peak
RSS. You give up 88% of your inventory and get back 61% of your runtime.

If you want OS packages only for *content* reasons, `--catalogers os` is the
right flag. If you wanted it for *speed*, it is not the lever you think it is.

### 2. The obvious fix for that was implemented, measured, and rejected

Excluding `/usr`, `/opt` and friends really does make an OS-only scan fast:
**~4 s**. It was built. It was measured. It was then **removed**, because it
silently drops deb licence coverage from **99% to 0%**.

The mechanism: dpkg package metadata comes from `/var/lib/dpkg/status`, but dpkg
*licences* are read from `/usr/share/doc/*/copyright`. Exclude `/usr` and every
deb in the report loses its `licenses` field — with no error, no warning, and a
report that still looks complete.

That trade is not worth four seconds, which is why `swinv` does not make it for
you and does not offer it as a preset. If you construct it yourself with
`--exclude './usr/**'`, know exactly what you are giving up.

### 3. `--no-file-ownership` is a speed lever, not a memory lever

It is the single fastest one-flag change measured (233 s vs 348 s, **~33%
faster**) and it uses **slightly more** memory (2414 MB vs 2271 MB). If you
reach for it to survive a small machine, you will make things marginally worse
on the axis you cared about.

It also has a correctness cost. The package/file ownership graph is what powers
`ExcludeBinaryPackagesWithFileOwnershipOverlap`, which stops the binary
classifier reporting `/usr/bin/python3.11` as a standalone `binary` component
when the `python3.11` deb already claims that file. Turn ownership off and those
duplicates come back.

Use it to buy speed when duplicates are acceptable. Never to buy RAM.

## What the Windows port taught us about the Linux scan

Building a Windows collector meant measuring things on Linux that had never been
questioned, because Windows made the same behaviour visible where Linux hides
it. Two findings apply here.

### The scan reads more than the tree it is scanning

Syft's directory resolver opens **every regular file** and reads about 3 KB of
it to determine a MIME type, before any cataloger runs. Measured on a scan of
`/usr`:

| | |
|---|---|
| tree on disk | 4.8 GB, 120,214 files |
| **read via syscalls** | **5.9 GB** |
| fetched from disk | 0 MB |

More than the whole tree, because most files are opened twice — once to sniff,
once by a cataloger. The `0 MB` is why nobody notices: the page cache serves it
all, so the cost is invisible on a warm system with local storage.

It stops being invisible on a cold cache, a network filesystem, or a spinning
disk, and it is most of why a full `/` scan takes minutes rather than seconds.
On Windows, where every open traverses an antivirus filter driver and no cache
helps, the same behaviour meant `C:\Program Files` did not finish inside ten
minutes.

### Almost none of that reading is necessary

The Windows collector's central insight is that a file a package manager already
accounts for does not need a version extracted from it — the package database
just said what it is. On Windows the uninstall registry accounted for 58% of
third-party executables. On Linux the equivalent figure is far higher:

| | |
|---|---|
| files under `/usr` | 120,214 |
| **claimed by a dpkg package** | **117,491 (97.7%)** |
| claimed by nothing | 2,723 (2.3%) |

So roughly 98% of the files Syft opens, sniffs and runs binary classifiers over
are files whose name, version and provenance `dpkg` states exactly. Syft does
discard the resulting duplicates — that is what
`ExcludeBinaryPackagesWithFileOwnershipOverlap` is for — but it discards them
*after* doing the work.

The 2.3% that no package claims is the interesting part, and it is the same
class of software the Windows `--full-scan` exists to find: unpacked tools,
vendor binaries, anything copied onto the machine.

**This is not currently actionable on Linux**, and the reason is worth stating.
On Windows swinv owns the pipeline, so it can read metadata first and open only
the remainder. On Linux it uses Syft as a library, and Syft's indexer opens
everything before any cataloger runs or any exclusion is consulted. Acting on
this would mean either an upstream change to Syft or writing a Linux collector
that does not use it — a much larger decision than a performance tweak, and one
that would trade away the cataloger coverage Syft provides for roughly 40
ecosystems.

Recorded here because the measurement is real and the reasoning transfers, not
because a change is proposed.

## `--max-memory`

`--max-memory SIZE` sets **Go's soft memory limit** (`debug.SetMemoryLimit`).
The garbage collector works proportionally harder as the limit is approached,
trading CPU for resident memory. Sizes accept both `512MiB` and `512MB`
spellings, and both mean 1024-based units; a bare number is bytes.

**It is soft by design.** If the genuinely live data exceeds the limit, `swinv`
keeps allocating rather than failing — a truncated inventory is worse than a
large one. The flag lowers peak RSS; it **cannot guarantee a ceiling**. Do not
size a cgroup limit as though it could.

The interesting result is that a moderate limit is not a trade at all:

> **`--max-memory 1536MiB` beat the default on both axes** — 30% less memory
> *and* 13% faster (1580 MB / 304 s vs 2271 MB / 348 s).

A smaller heap means less memory for the collector to scan and better cache
locality, so the usual space-for-time trade does not appear until the limit gets
genuinely tight. If you change exactly one thing, change this. It is not the
default — a fixed cap is the wrong thing to bake in for unknown hardware — but
`packaging/swinv.service` carries it as a commented example.

Push harder and the trade does arrive. `--max-memory 768MiB --parallelism 1`
reaches **1085 MB**, the lowest figure measured, at **615 s** — nearly double the
default runtime.

## A worked example of why exclusions dominate

The clearest evidence for everything above came from a Fedora 44 guest under
WSL2, and it was an accident.

`/usr/lib/wsl` is a `9p` mount through which WSL projects the Windows host's
driver packages into the guest. Until `v0.1.1`, `9p` was not in the non-local
filesystem list, so the scan walked it:

| | Components | Wall time |
|---|---|---|
| Before (`9p` walked) | 1,003 | 133.6 s |
| After (`9p` excluded) | 526 | **5.1 s** |

**A 26× speedup from one exclusion.** The 477 components that disappeared were
never that machine's software — they were Windows binaries and .NET assemblies
belonging to the host. So the tree being walked was simultaneously the largest
cost and pure noise.

Two things generalise from this:

- **The walk is the cost, and remote-backed filesystems are the worst kind of
  walk.** `9p`, like NFS or CIFS, crosses a boundary on every `stat` and every
  read. A tree that would take a second on local disk can take minutes through
  one.
- **The most expensive thing to scan is often the thing you least wanted.**
  Mounted shares, extracted images and host projections tend to be both large
  and irrelevant. Getting the exclusions right is not a micro-optimisation; on
  this host it was the difference between five seconds and two minutes, and
  between a correct inventory and one that was half wrong.

## Tuning guide

Ordered by effect. Do the first thing before considering the second.

1. **Exclusions.** Nothing else is close. Every path not walked is time not
   spent and index not allocated. Find the big trees on your host that are not
   installed software — build outputs, data directories, artefact caches,
   scratch space — and exclude them explicitly:

   ```sh
   swinv --exclude './opt/build/**' --exclude './srv/data/**'
   ```

   Patterns are relative to the scan root and **must** start with `./`, `*/` or
   `**/`; anything else is a usage error (exit 2). Check the defaults below
   before adding your own — a lot is already covered.

2. **Mount hygiene.** Confirm the automatic non-local filesystem skipping is
   doing its job (it is on by default). Walking a mounted NFS share is the
   single biggest cause of a scan taking hours instead of minutes. The final
   exclusion list is always recorded in `scan.excluded`, so read it from a real
   report rather than assuming.

3. **`--max-memory 1536MiB`.** Best single-flag change measured: less memory and
   less time. Scale it to the host; on a small box start lower and expect to pay
   in runtime.

4. **`--parallelism`.** Lower it only in combination with `--max-memory`, and
   only when memory is the binding constraint. On its own it is close to a
   no-op for time (`--parallelism 2`: 322 s vs 348 s) and buys little memory.

5. **`--no-file-ownership`.** ~33% faster, at the price of duplicate
   binary/package components and slightly more memory. A deliberate trade, not a
   default.

Things *not* to reach for: `--catalogers os` as a speed measure (finding 1), and
excluding `/usr` (finding 2).

### Memory-constrained host

Lowest peak RSS measured — 1085 MB, at nearly double the runtime:

```sh
swinv --max-memory 768MiB --parallelism 1 --out /var/lib/swinv
```

### Fastest useful scan

Start from the exclusions for your host, then add the speed lever. Accept the
duplicate binary/package components it reintroduces:

```sh
swinv --no-file-ownership --exclude './opt/build/**' --out /var/lib/swinv
```

The `--no-file-ownership` figure (233 s) was measured on its own; combining it
with `--max-memory` was not measured here, so treat that pairing as untested
rather than as an additive win.

### Attributing a regression

`--verbose` prints per-stage timings to stderr — symlink preflight, source
construction, cataloging, conversion, and hashing when `--hash` is on — which is
enough to tell a slow walk from a slow parse:

```sh
swinv --verbose --out /tmp/inv
```

## `/home` and `/root` are excluded by default

This is the largest single exclusion `swinv` makes, and it is a deliberate
decision rather than an oversight.

On the test host, `/home` alone was **508,687 files and 40 GB across 86
`node_modules` trees** — more than the entire rest of the filesystem combined.
Adding it to a full scan does not produce a comparable run; the configuration
was attempted and abandoned rather than measured, so no wall-time figure is
published for it here. Home directories are also per-user, high-churn, and
privacy-sensitive, none of which is true of the machine's own software. For a
fleet inventory feeding asset management, the managed system-wide surface is the
signal you want.

`--include-home` opts back in, which is the right choice for a developer
workstation where the interesting software genuinely lives under `$HOME`.

**The skip is never silent.** Either way the choice is recorded: `/home` and
`/root` appear in `scan.excluded`, and a warning lands in `scan.warnings`:

```
user home directories (/home, /root) were not scanned; pass --include-home to include them
```

A consumer can therefore always tell what a given report covers.

## Snap and Flatpak are included by default

Both are genuinely installed software, so both are scanned. `--no-snap` and
`--no-flatpak` opt out (excluding `./snap/**` and `./var/lib/flatpak/**`
respectively), each recording a warning that the corresponding packages will be
missing from the inventory.

There is a subtlety worth understanding, because it is exactly the kind of thing
that goes wrong quietly. **Snaps are squashfs loop mounts**, and `squashfs` is in
the non-local filesystem skip list below. Left alone, the mount rule would have
excluded every snap on the machine — silently defeating the decision to include
them, and making `--no-snap` a no-op that changed nothing.

The resolution: `squashfs` stays in the non-local set, but mount points under
`/snap/` and `/var/lib/snapd/snap/` are **carved out** of that rule unless
`--no-snap` was passed. A squashfs image mounted anywhere else — an ISO, an
appliance payload — is still excluded, which is correct: that is not installed
software on this host.

## The default exclusions

Applied only when the scan root is `/`. Any other root is an arbitrary tree
whose layout `swinv` cannot assume, so it gets no layout defaults.

| Group | Paths |
|---|---|
| Kernel-synthetic | `./proc/**` `./sys/**` `./dev/**` |
| Volatile | `./run/**` `./tmp/**` `./var/tmp/**` |
| Caches and logs | `./var/cache/**` `./var/log/**` `./var/spool/**` |
| Crash and backup state | `./var/crash/**` `./var/backups/**` `./var/lib/systemd/coredump/**` |
| Container image stores | `./var/lib/docker/**` `./var/lib/containers/**` `./var/lib/containerd/**` `./var/lib/kubelet/pods/**` |
| Removable and foreign | `./mnt/**` `./media/**` `./lost+found/**` |
| Large opaque files | `./swapfile` `./swap.img` |
| Noise, at any depth | `**/.git/**` `**/__pycache__/**` `**/.cache/**` |
| User homes (unless `--include-home`) | `./home/**` `./root/**` |

Container image stores are excluded because their contents belong to a different
machine image, not to this host.

`--exclude` appends to this list; it never replaces it.

### Non-local filesystem skipping

`swinv` also reads `/proc/self/mountinfo` and excludes every mount point whose
filesystem type is not local:

```
nfs  nfs4  cifs  smb3  fuse.sshfs  fuse.rclone  autofs  overlay
squashfs  tmpfs  devtmpfs  proc  sysfs  cgroup  cgroup2
```

Network filesystems turn a local scan into a remote one; automounters would be
triggered by the walk itself; virtual and in-memory filesystems hold no
installed software. Syft does not do this for you.

Details that matter in practice:

- The root mount `/` is never excluded, whatever its type — that would exclude
  the entire scan.
- Mount points are octal-escaped by the kernel (`\040` for a space) and are
  unescaped before use.
- Unparsable mount-table lines are skipped, never fatal.
- `/snap` and `/var/lib/snapd/snap` are carved out of the `squashfs` rule, as
  above.
- `--no-auto-exclude-mounts` disables the whole mechanism. On a host with an NFS
  mount, expect a scan measured in hours.
- Whatever the outcome, the complete final exclusion list — defaults, mount
  points, your own patterns, and any symlinks quarantined by the preflight — is
  written to `scan.excluded`, and the auto-excluded mount points are summarised
  in `scan.warnings`.

## Measuring it yourself

Do this. None of the numbers above describe your fleet.

`make bench` builds the binary and times a scan of the fixture tree in
`testdata/rootfs`, reporting wall time and peak RSS via GNU `/usr/bin/time -v`
(it degrades to wall-clock only if that is unavailable):

```sh
make bench
```

That gives you a fast, stable regression check, not a production estimate — the
fixture is deliberately tiny. For a real figure, time a real scan:

```sh
/usr/bin/time -v ./bin/swinv --out /tmp/inv --quiet
```

The two lines to read from its output:

```
Elapsed (wall clock) time (h:mm:ss or m:ss): ...
Maximum resident set size (kbytes): ...
```

To compare configurations honestly:

- Change **one flag at a time**, and confirm the component count is unchanged
  before believing a speed-up. A configuration that is faster because it found
  less is not faster.
- Run each configuration twice and take the second. The first run pays for a
  cold page cache; the difference is large on a walk-dominated workload.
- Use `--quiet` so stderr formatting is not in the measurement, and `--out` a
  scratch directory so you are not racing your real inventory.
- Add `--verbose` on a separate run to see which stage moved.
