# swinv troubleshooting

Symptoms an operator actually hits when running `swinv`, what causes each one,
and what to do about it.

Part of the [swinv](../README.md) documentation.

---

## Quick triage

| Symptom | Section |
|---|---|
| `components` is empty, or far smaller than expected | [Zero components](#the-scan-produced-zero-components) |
| Exit code 1, `scan.incomplete` is `true` | [Exit code 1](#exit-code-1--scanincomplete-is-true) |
| Scan runs for tens of minutes, or hits the timeout | [Too slow](#the-scan-takes-far-too-long) |
| Peak RSS in the gigabytes, or the OOM killer fires | [Too much memory](#it-used-far-more-memory-than-expected--got-oom-killed) |
| `invalid exclusion pattern` | [Exclusion patterns](#invalid-exclusion-pattern) |
| `unrecognized import path "golang.org/toolchain"` | [Toolchain](#build-fails-with-unrecognized-import-path-golangorgtoolchain) |
| `sqlite driver is required for cataloging newer RPM databases` | [SQLite driver](#sqlite-driver-is-required-for-cataloging-newer-rpm-databases) |
| No `product_serial` / `product_uuid`, packages missing under other users' homes | [Non-root](#missing-dmi-serialuuid-or-missing-packages-under-other-users-home-directories) |
| `--since` reports the whole machine as added or removed | [Deltas](#--since-says-everything-was-addedremoved) |
| `--out` directory filling up | [Retention](#disk-filling-up-in-timestamped-mode) |

## Read the report first

Almost every question is answered by the report `swinv` just wrote. `swinv` is
loud on `stderr` and records the same information in the JSON, so start there:

```sh
jq '.scan.incomplete'          web-01-latest.json   # did a cataloger fail?
jq -r '.scan.warnings[]?'      web-01-latest.json   # why the scan is degraded
jq -r '.scan.excluded[]'       web-01-latest.json   # every path pattern skipped
jq '.components | length'      web-01-latest.json   # how much was found
jq '.scan.ran_as_root, .scan.duration_ms' web-01-latest.json
```

`--verbose` adds a per-stage timing breakdown on `stderr` — symlink preflight,
source construction, cataloging, conversion — which tells you which stage is
responsible before you start changing flags:

```console
$ swinv --root /opt/code/swinv/testdata/rootfs --out /tmp/inv --verbose
swinv: excluding 0 path patterns
swinv: scanning /opt/code/swinv/testdata/rootfs ...
swinv: symlink preflight completed in 651µs (0 symlink(s) quarantined)
swinv: source constructed in 391µs (root /opt/code/swinv/testdata/rootfs, 0 exclusion patterns)
swinv: cataloging completed in 1.498s
swinv: conversion completed in 263µs (7 components)
swinv: found 7 components in 1499ms
swinv: wrote /tmp/inv/web-01-20240309.json
```

On a real root the same four stage lines appear with the pattern count, the
number of quarantined symlinks, and the component count filled in for that host.

Exit codes, for scripting:

| Code | Meaning |
|---|---|
| 0 | Success; a complete inventory was written |
| 1 | Partial success; output written but `scan.incomplete` is `true` |
| 2 | Usage error (bad flag, bad exclusion pattern, unusable `--since` baseline) |
| 3 | Fatal: could not construct the source, or could not write output |
| 4 | `--timeout` exceeded |

---

## "The scan produced zero components."

### The historical cause: one unreadable symlink

This was a real failure on a live Ubuntu host running unprivileged: **zero
components after a five-minute scan**, with

```
unable to index filesystem path="/root/.local/share/uv/.../python3.12":
  lstat /root/.local: permission denied
```

The bug is upstream, [anchore/syft#3286](https://github.com/anchore/syft/issues/3286).
When Syft's directory indexer meets a symlink it queues the link's **target** as
an *additional root* to index — `addSymlinkToIndex` returns the target unless
`os.Stat` reports `ENOENT`, so a *permission* error still queues it. Each
additional root is then resolved with `filepath.EvalSymlinks` **before any
path-index visitor runs**, and `indexAllRoots` treats a failure there as fatal to
the entire scan. A single virtualenv symlink,
`/opt/.../.venv12/bin/python -> /root/.local/.../python3.12`, was enough to lose
everything.

**Excluding the target does not help.** This was tested, not assumed:
`--exclude './root/**'` failed identically, because the fatal resolution happens
before exclusions are consulted.

### What swinv does about it

`swinv` runs a **symlink preflight** (`internal/scan/preflight.go`) before Syft
is handed anything: an lstat-only walk that finds symlinks whose target cannot be
resolved and excludes **the links themselves**, so the indexer never queues the
bad root. That is what took the scan from 0 to 14,190 components on the affected
host.

- Quarantined links are added to `scan.excluded`.
- A warning naming up to five of them is added to `scan.warnings`.
- Software reachable *only* through a quarantined link is not in the inventory.
  That is the trade: a partial inventory instead of none.
- The preflight is not disableable from the CLI. It should be removed only when
  upstream fixes #3286.

```sh
jq -r '.scan.warnings[]? | select(startswith("excluded") and contains("symlink"))' \
  web-01-latest.json
```

### If you still see zero components

Work down this list:

1. **Check the stage timings.** `--verbose` prints
   `symlink preflight completed in ... (N symlink(s) quarantined)`. If N is 0 and
   cataloging still failed with `unable to index filesystem path=...`, the
   preflight did not see the offending link.
2. **Check for a preflight warning.** If `scan.warnings` contains
   `symlink preflight did not complete`, the lstat walk itself aborted and a bad
   symlink may still be present.
3. **The preflight only honours `./`-anchored exclusion patterns.** `*/` and
   `**/` patterns are ignored there, so those paths are still walked — deliberate,
   because over-skipping in the preflight would let through exactly the symlink it
   exists to catch. This means the preflight can only *miss* a link that lives
   under a `./`-excluded tree, which Syft would not index either.
4. **Exclude the link, never the target.** If the error names a path, exclude the
   symlink itself:

   ```sh
   swinv --exclude './opt/build/.venv12/bin/python'
   ```

5. **Run as root.** Most instances of this failure are a permission error on
   another user's home directory; as root the target resolves and nothing is
   quarantined.

### The other causes of an empty or thin inventory

| Check | Command |
|---|---|
| Is `--root` pointing at an empty or wrong tree? | `jq -r '.scan.root' out.json` |
| Did your own `--exclude` swallow the system? | `jq -r '.scan.excluded[]' out.json` |
| Did `--catalogers` select nothing useful? | `jq -r '.scan.catalogers[]?' out.json` |
| Did a cataloger fail outright? | `jq -r '.scan.warnings[]?' out.json` |

Note that `DefaultExcludes` only applies when the scan root is `/`. Any other
root is an arbitrary tree whose layout `swinv` will not assume, so a
`--root /some/image` scan starts with no exclusions at all.

---

## "Exit code 1 / `scan.incomplete` is true."

**This is by design, not a crash.** A single cataloger failing must never abort
the run: the failure is recorded in `scan.warnings`, `scan.incomplete` is set to
`true`, the output is written anyway, and the exit code is 1. An inventory
missing one ecosystem is far more useful than no inventory.

So: **the files are there and are valid.** Read them, then read the warning.

```sh
swinv --out /var/lib/swinv; rc=$?
jq -r '.scan.warnings[]?' /var/lib/swinv/*-latest.json
```

The warning that sets `incomplete` reads:

```
cataloging did not complete, the inventory may be missing packages: <error>
```

Other entries in `scan.warnings` are informational and do **not** set
`incomplete` — they are there so a consumer can tell what was skipped:

| Warning | Meaning |
|---|---|
| `not running as root: root-only paths and DMI identifiers were skipped` | Expected for an unprivileged run |
| `user home directories (/home, /root) were not scanned; ...` | Default behaviour; `--include-home` opts in |
| `auto-excluded N non-local filesystem mount point(s): ...` | NFS/CIFS/tmpfs/etc. skipped |
| `excluded N symlink(s) whose target could not be resolved ...` | Symlink preflight, above |
| `N files could not be identified` | Syft's `Unknowns` count; normal on any host |
| `N shared evidence file(s) ... were not hashed` | `--hash` only; see below |
| `--since baseline was taken on "x" but this host is "y" ...` | See the delta section |

For a scheduled job, treat exit 1 as "collected, with a caveat" rather than as a
failure:

```sh
swinv --out /var/lib/swinv || [ $? -eq 1 ]
```

Exit **3** is the genuine failure — the source could not be constructed or the
output could not be written; nothing usable was produced. Exit **4** means the
`--timeout` deadline (default `30m`) expired.

---

## "The scan takes far too long."

`swinv` is dominated by the filesystem walk, not by parsing. Check these in
order.

### 1. Is a network filesystem being walked?

Scanning a mounted NFS share is the single biggest cause of a scan taking hours
instead of minutes. `swinv` reads `/proc/self/mountinfo` and excludes every mount
whose filesystem type is non-local (`nfs`, `nfs4`, `cifs`, `smb3`, `fuse.sshfs`,
`fuse.rclone`, `autofs`, `overlay`, `squashfs`, `tmpfs`, `devtmpfs`, `proc`,
`sysfs`, `cgroup`, `cgroup2`).

That guard is on by default. If someone passed `--no-auto-exclude-mounts`,
**remove it.** Confirm what was skipped:

```sh
jq -r '.scan.warnings[]? | select(startswith("auto-excluded"))' out.json
findmnt -rno TARGET,FSTYPE -t nfs,nfs4,cifs,fuse.sshfs   # what is mounted
```

A warning of the form `could not read /proc/self/mountinfo (...)` means the
guard could not run at all — the scan is still correct, only slow.

Note the deliberate carve-out: snaps are squashfs loop mounts, and mount points
under `/snap` and `/var/lib/snapd/snap` are exempted from the squashfs rule
unless `--no-snap` is passed. A squashfs image mounted anywhere else — an ISO, an
appliance payload — stays excluded.

### 2. Is `--include-home` on?

Turn it off. On the development host `/home` alone was 508,687 files and 40 GB
across 86 `node_modules` trees — more than the entire rest of the filesystem
combined, and a full scan with home included did not finish in a comparable
time. `/home` and `/root` are excluded by default for exactly this reason.

### 3. Are there large source trees under `/opt` or `/srv`?

These are not excluded by default because they legitimately hold installed
software. A developer checkout is a different matter — the reference host carried
156k files of `node_modules` under `/opt`. Exclude the checkout, not the tree:

```sh
swinv --exclude './opt/build/**' --exclude './srv/git/**'
```

`**/.git/**`, `**/__pycache__/**` and `**/.cache/**` are already excluded at any
depth.

### 4. Raise the deadline if you must

The default `--timeout 30m` produces exit code 4 when exceeded. Raise it rather
than let a slow host produce nothing:

```sh
swinv --timeout 60m --out /var/lib/swinv
```

### `--catalogers os` will not fix this

This is the most common wrong turn. **Syft indexes the entire filesystem when it
builds the directory resolver, *before* cataloger selection is applied.**
Narrowing catalogers narrows the parsing, not the walk. Measured on the reference
host: `--catalogers os` took **135 s**, against a 2 s target for OS-only
collection.

The obvious follow-up — also excluding `/usr` and `/opt` — does get an OS-only
scan to about 4 s, and it is a trap: **dpkg licences are read from
`/usr/share/doc/*/copyright`**, so excluding `/usr` silently drops deb licence
coverage from 99% to 0%. That optimisation was implemented, measured, and
rejected. Do not reintroduce it.

For the measured numbers and the full reasoning, see
[docs/PERFORMANCE.md](PERFORMANCE.md).

---

## "It used far more memory than expected / got OOM-killed."

Peak RSS is dominated by **Syft's in-memory index of every path it walked**, not
by anything in `swinv` itself. The effective levers are therefore the ones that
shrink the walk (exclusions) or bound the heap (`--max-memory`).

Measured on the reference host, every row producing the same inventory:

| Configuration | Wall | Peak RSS |
|---|---|---|
| default | 348 s | 2271 MB |
| `--no-file-ownership` | 233 s | 2414 MB |
| `--parallelism 2` | 322 s | 2197 MB |
| `--parallelism 1 --no-file-ownership` | 325 s | 1735 MB |
| **`--max-memory 1536MiB`** | **304 s** | **1580 MB** |
| `--max-memory 768MiB` | 546 s | 1337 MB |
| `--max-memory 768MiB --parallelism 1` | 615 s | **1085 MB** |

**If you change one thing, change `--max-memory`.** At `1536MiB` it beat the
default on both axes — 30% less memory *and* 13% faster — because a smaller heap
means less to scan and better cache locality.

```sh
swinv --max-memory 1536MiB --out /var/lib/swinv          # first thing to try
swinv --max-memory 768MiB --parallelism 1 --out /var/lib/swinv   # constrained host
```

`--max-memory` sets Go's soft memory limit: the garbage collector works
proportionally harder as the limit is approached. It is *soft* by design — if the
genuinely live data exceeds it, `swinv` still allocates rather than failing,
because a truncated inventory is worse than a larger one. It lowers peak RSS; it
cannot guarantee a ceiling. Do not set a `MemoryMax=` in the systemd unit and
expect a clean result — that will get the process killed, not slowed.

> **`--no-file-ownership` will NOT help.** It is roughly 33% faster but uses
> slightly **more** memory (2414 MB against the default's 2271 MB). Use it to buy
> speed, never RAM — and note it reintroduces binary/package duplicates, because
> file ownership is what lets Syft drop a `binary` component already claimed by
> an OS package.

Then reduce the walk itself: exclude large trees (previous section), and leave
`--include-home` off.

---

## `invalid exclusion pattern`

```console
$ swinv --exclude '/var/cache/**'
swinv: invalid exclusion pattern "/var/cache/**": exclusion patterns are relative
to the scan root and must start with "./", "*/", or "**/" (for example
"./var/cache/**" to skip a directory tree, or "**/*.iso" to skip a file anywhere)
```

Exit code 2. Exclusion patterns are matched **relative to the scan root**, so
they must begin with `./`, `*/`, or `**/`. An absolute pattern such as
`/var/cache/**` would silently match nothing; a bare `var/cache/**` is rejected
outright by Syft's source construction. `swinv` validates them at startup so the
error names the offending pattern instead of surfacing later as a cataloging
failure.

| Want | Pattern |
|---|---|
| Skip a directory tree | `./opt/build/**` |
| Skip a single file | `./swapfile` |
| Skip a name at any depth | `**/node_modules/**` |
| Skip a name one level below the root | `*/scratch/**` |

Quote the pattern so your shell does not glob it.

---

## Build fails with `unrecognized import path "golang.org/toolchain"`

Your Go toolchain is older than **1.26.3** and cannot auto-download a newer one.
Syft v1.51.0 declares `go >= 1.26.3` in its `go.mod`.

`swinv` is built and pinned against **Go 1.26.6**. Install a current Go and put
it first on `PATH`:

```sh
export PATH=/usr/local/go/bin:$PATH
go version          # want go1.26.6 or newer
make build
```

---

## `sqlite driver is required for cataloging newer RPM databases`

Only relevant if you are building a modified copy of `swinv`. **The blank import
of `modernc.org/sqlite` in `internal/scan` is load-bearing — do not remove it.**

As of v1.51.0 Syft no longer registers a SQLite driver itself; it requires the
*consumer* to do it (Syft's own `cmd/syft/main.go` does exactly this import).
Without it, `CreateSBOM` does not merely skip RPM databases — it **fails
outright**, on any host, **including hosts with no RPM database at all**.

The driver is pure Go, so `CGO_ENABLED=0` and the static binary are unaffected.
Restore the import:

```go
// internal/scan/scan.go
import (
	// ...
	_ "modernc.org/sqlite"
)
```

```sh
grep -rn 'modernc.org/sqlite' internal/scan/
make build
```

---

## Missing DMI serial/UUID, or missing packages under other users' home directories

**Expected when running as a non-root user. Never an error.**

A non-root run is fully supported and exits 0. It records:

```json
"scan": {
  "ran_as_root": false,
  "warnings": ["not running as root: root-only paths and DMI identifiers were skipped"]
}
```

`host.product_serial` and `host.product_uuid` come from
`/sys/class/dmi/id/product_serial` and `product_uuid`, which are root-readable
only. On `EACCES` they are left empty and no separate warning is emitted —
`hostfacts` never turns a missing or unreadable file into an error. The same
applies to any package under a directory the user cannot traverse.

The fix, if you need those fields, is to run as root:

```sh
sudo swinv --out /var/lib/swinv
```

The shipped `packaging/swinv.service` runs as root for this reason. Related:
unprivileged runs are also where the symlink-quarantine warning shows up, since
the unresolvable targets are usually other users' home directories.

Note that firmware placeholder strings (`To Be Filled By O.E.M.`,
`Default string`, `System Serial Number`, the all-zero UUID) are deliberately
mapped to empty, so an empty field on a root run may simply mean the board never
had a real serial programmed.

---

## `--since` says everything was added/removed

Two causes, and `swinv` tells you which.

### You compared against a different machine's report

Permitted, but recorded as a warning — otherwise it silently looks like the whole
system was replaced:

```
--since baseline was taken on "web-02" but this host is "web-01"; the delta
compares two different machines
```

```sh
jq -r '.delta.baseline_host, .host.hostname' out.json
```

Use each host's own baseline. The `-latest` symlink is what makes this easy:

```sh
swinv --out /var/lib/swinv --output-mode timestamped \
      --since /var/lib/swinv/*-latest.json
```

### You compared against a `--delta-only` file

Refused outright, exit code 2:

```console
$ swinv --since /var/lib/swinv/web-01-latest.json
swinv: --since: /var/lib/swinv/web-01-latest.json was written with --delta-only
and holds only changed components, so it cannot be used as a baseline; use a
full inventory report instead
```

A `--delta-only` report contains only what changed, so diffing against it would
report every unchanged package on the machine as newly added. The report marks
itself with `delta.delta_only`, which is what the guard checks:

```sh
jq '.delta.delta_only // false' baseline.json    # true => unusable as a baseline
```

Fix it by keeping a full inventory as the baseline. `--delta-only` is for the
*output* you ship to a change feed, not for the file you keep on disk — the
default (delta **plus** the full component list) keeps the file self-contained
and reusable.

Note that this check runs *after* the scan, so the exit-2 message appears at the
end of a full run, not at startup.

Two things that are **not** causes: a schema-version mismatch (any schema version
is accepted as a baseline, so deltas survive an `swinv` upgrade), and a package
upgrade (matching is on `(name, type)` only, deliberately not on version, so an
upgrade reads as one `changed` entry rather than a removal plus an addition).

---

## Disk filling up in timestamped mode

`--output-mode timestamped` writes **a brand-new file for every run and keeps it
forever**. There is no built-in retention in `swinv` — it writes files and stops
there. If a daily timer has been running for a year, you have a year of files.

Check what you have:

```sh
du -sh /var/lib/swinv
ls -1 /var/lib/swinv | wc -l
```

Pick one of these:

**Retain 90 days with `find`** (run from cron, or as an `ExecStartPost=`):

```sh
find /var/lib/swinv -maxdepth 1 -type f \( -name '*.json' -o -name '*.csv' \
     -o -name '*.ndjson' \) -mtime +90 -delete
```

`*.json` also covers `*.cdx.json`. Do not use `-delete` on the whole directory:
`-type f` matters, because it is what leaves the `-latest` symlinks alone.

### `hostname: command not found`, or a path with nothing before `-latest.json`

`hostname` is not installed on a minimal Fedora, on many container images, or
on hardened builds — it is a separate package, not part of coreutils. A command
written as `$(hostname)-latest.json` then expands to just `-latest.json` and
fails with a confusing "no such file" naming a path you never typed:

```console
$ swinv --since /var/lib/swinv/$(hostname)-latest.json
bash: hostname: command not found
swinv: --since: reading baseline report: open /var/lib/swinv/-latest.json: no such file or directory
```

Use a glob instead. `swinv` writes exactly one `-latest.<ext>` per host into a
given `--out` directory, so it can only match one file:

```sh
swinv --since /var/lib/swinv/*-latest.json
```

If you genuinely need the name, `uname -n` is in coreutils and is always
present. Note it may differ from the filename: `swinv` strips characters that
have no business in a path, so a host called `web-01.corp.example` writes
`web-01.corp.example-latest.json` but one with unusual characters may not.

**Or use logrotate** with `daily`/`rotate 90` on `/var/lib/swinv/*.json`.

**Or stop accumulating files at all.** If you only ever consume the newest
inventory, `timestamped` is the wrong mode:

| Mode | Files produced | Growth |
|---|---|---|
| `dated` *(default)* | `web-01-20240309.json` | one per day |
| `overwrite` | `web-01.json` | none — one fixed file, replaced atomically |
| `timestamped` | `web-01-20240309T140506Z.json` | one per run, forever |

Whatever you choose, **consumers should follow the `-latest` symlink**, not
guess at filenames:

```sh
rsync -a /var/lib/swinv/*-latest.json collector:/inventory/
```

`{hostname}-latest.json` / `.csv` are maintained on by default
(`--latest-symlink`), updated atomically, and point at the newest file by
relative name — which is why a cleanup that deletes files must leave the symlinks
themselves in place. Note also that `cyclonedx-json` output is roughly twice the
size of the JSON, so dropping it from `--format` is an easy saving if nothing
consumes it.

---

## How to file a good bug report

Include all of the following. Most of it is one command each.

**1. Version, commit, and the Syft version it was built against.**

```console
$ swinv --version
swinv dev (commit none, syft v1.51.0, linux/amd64)
```

**2. The warnings array** — this is the single most useful field, and it is where
`swinv` records everything that degraded the scan.

```sh
jq -r '.scan.warnings[]?' /var/lib/swinv/*-latest.json
```

**3. The effective exclusion list**, including anything the mount-table guard or
the symlink preflight added:

```sh
jq -r '.scan.excluded[]' /var/lib/swinv/*-latest.json
```

**4. Stage timings from `--verbose`**, so a slowdown or failure is attributable to
the preflight, the source construction, cataloging, or conversion:

```sh
swinv --root / --out /tmp/inv --verbose 2>&1 | tee /tmp/swinv-verbose.log
```

**5. Distro and whether it ran as root:**

```sh
jq -r '.host.os_pretty_name, .host.kernel_release, .host.architecture,
       .scan.ran_as_root, .scan.incomplete, .scan.duration_ms' \
   /var/lib/swinv/*-latest.json
```

**6. The exit code**, and the full `stderr` text of the run.

If the report itself is the problem, a `.scan` block plus one offending component
is usually enough — do **not** attach a full inventory. It carries hostname,
machine ID, MAC addresses, IP addresses, DMI serial and UUID, and the complete
software list of the machine.

A minimal reproduction is worth a great deal here. `swinv --root <tree>` scans an
arbitrary directory instead of `/`, so a failure can often be reduced to a small
fixture tree:

```sh
swinv --root /tmp/repro --out /tmp/repro-out --verbose
```
