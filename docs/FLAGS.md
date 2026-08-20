# swinv flag reference

Every command-line flag, its default, its exact behaviour, and the exit codes.
Part of the [swinv](../README.md) documentation.

## Synopsis

```
swinv [flags]
```

`swinv` takes **no positional arguments** — passing one is a usage error. It
scans the machine it runs on, enumerates installed software, and writes the
result to local files. Nothing is sent over the network.

Flags are parsed by the Go standard `flag` package, so `-flag`, `--flag`,
`-flag=value` and `-flag value` are all accepted. This document writes the
double-dash form throughout; the built-in help prints the single-dash form.

```console
$ swinv -h        # usage to stderr, exit 0
$ swinv --version # version to stdout, exit 0
swinv dev (commit none, syft v1.51.0, linux/amd64)
```

`--version` short-circuits every other check, so it works even alongside flags
that would otherwise be rejected.

## Flags

### Scope and target

| Flag | Default | Meaning |
|---|---|---|
| `--root PATH` | `/` | Filesystem root to scan |
| `--include-home` | `false` | Also scan `/home` and `/root` |
| `--offline` | `false` | Skip the reverse-DNS lookup used for `host.fqdn`. The only network activity swinv performs; with this set the run is completely network-silent. |
| `--perm OCTAL` | `0644` | Permission bits for the report files. The output directory gets the same bits plus execute wherever read is granted, so `0644`→`0755`, `0640`→`0750`, `0600`→`0700`. Setuid, setgid and sticky are refused rather than silently dropped. |
| `--skip-nested-rootfs` | `false` | Drop components whose package-database evidence comes from a nested root filesystem (an extracted image, container rootfs, chroot or test fixture) rather than the scanned host. Off by default: scanning such a tree is sometimes the point. |
| `--no-snap` | `false` | Exclude `/snap` |
| `--no-flatpak` | `false` | Exclude `/var/lib/flatpak` |
| `--catalogers EXPR` | *(none)* | Cataloger selection expression, e.g. `os` |
| `--no-file-ownership` | `false` | Skip package-file ownership (faster, but reintroduces binary/package duplicates) |
| `--require-host-id` | `false` | Fail if `/etc/machine-id` is empty or unreadable |

`--root` other than `/` disables the built-in filesystem-layout exclusions
entirely: they describe a running Linux system, and any other root is an
arbitrary tree (a fixture, a mounted image) whose layout `swinv` cannot assume.
Only `--exclude` patterns you supply apply there. Host FQDN lookup is also
skipped for a non-`/` root, so scanning a fixture stays hermetic.

`--require-host-id` exits **3**, not 2 — it is a fatal runtime condition, not a
usage problem.

### Output

| Flag | Default | Meaning |
|---|---|---|
| `--out DIR` | `/var/lib/swinv` | Output directory; created `0755` if missing, files written `0644` |
| `--output-mode MODE` | `dated` | `dated`, `overwrite`, or `timestamped` — see below |
| `--name TEMPLATE` | *(from `--output-mode`)* | Output basename; `{hostname}`, `{machine_id}`, `{date}`, `{datetime}` |
| `--format LIST` | `json,csv` | Comma-separated: `json`, `csv`, `ndjson`, `cyclonedx-json` |
| `--stdout` | `false` | Write to stdout instead of files; requires exactly one `--format` |
| `--latest-symlink` | `true` | Maintain `{hostname}-latest.{ext}` symlinks in `--out` |

Format names map to file extensions as follows:

| `--format` | Extension |
|---|---|
| `json` | `.json` |
| `csv` | `.csv` |
| `ndjson` | `.ndjson` |
| `cyclonedx-json` | `.cdx.json` |

Names are matched case-insensitively and surrounding whitespace is ignored;
duplicates in the list are collapsed. An unknown name is a usage error.

Every file is written atomically — temp file in the same directory, `fsync`,
`rename`, `fsync` of the directory — so a collector can never read a
half-written inventory. The `-latest` symlinks are replaced atomically too, and
a symlink that would collide with the output file itself is skipped rather than
overwriting it. A failure to update a symlink is a warning on stderr, not a
failed run: it is not worth discarding a good inventory over.

### Exclusions

| Flag | Default | Meaning |
|---|---|---|
| `--exclude GLOB` | *(none)* | Additional exclusion pattern; repeatable, appended to the defaults |
| `--no-auto-exclude-mounts` | `false` | Do not auto-exclude non-local filesystems |

The final exclusion list — defaults, mount-derived exclusions, your patterns,
and any symlinks quarantined by the preflight — is always recorded in
`scan.excluded`.

### Change detection

| Flag | Default | Meaning |
|---|---|---|
| `--hash` | `false` | Record a SHA-256 of each component's primary file |
| `--since PATH` | *(none)* | Compare against a previous swinv JSON report and emit a delta |
| `--delta-only` | `false` | With `--since`, emit only the changed components |

### Resources

| Flag | Default | Meaning |
|---|---|---|
| `--debug-stacks-after DUR` | `0` (never) | If the scan is still running after this long, write every goroutine stack to a file and carry on |
| `--fast` | `false` | Scan at normal scheduling priority and full parallelism |
| `--max-memory SIZE` | *(unlimited)* | Soft memory limit, e.g. `1536MiB` |
| `--parallelism N` | `0` | Cataloger parallelism; `0` chooses automatically — see below |
| `--timeout DURATION` | `30m` | Whole-run deadline (Go duration syntax: `90s`, `10m`, `2h`) |

`--parallelism` must not be negative and `--timeout` must be positive;
either is a usage error.

`--debug-stacks-after` is for a scan that appears to have hung. Go dumps every
goroutine stack on `SIGQUIT`, and on Windows on Ctrl+Break, but neither is
reachable from a systemd timer or a scheduled task, and many laptop keyboards
have no Break key at all. This flag produces the same information on a timer:

```console
$ swinv --root / --out /var/lib/swinv --debug-stacks-after 60s
swinv: scanning / ...
swinv: still scanning (30s elapsed, deadline 30m0s)
swinv: wrote goroutine dump to /var/lib/swinv/swinv-stacks-20260820T084719Z.txt after 1m0s
```

The scan is not interrupted; the dump is taken from alongside it, while the
stacks still show what the scan is doing. Waiting for the run to fail and
dumping afterwards would be too late — by then the deadline has unwound the
worker goroutines and the frame that explains the stall is gone. If the output
directory is not writable the dump falls back to the temp directory.

#### swinv is deliberately slow by default

An inventory collector is background maintenance. It runs unattended, on a
timer, on machines doing real work, and nobody is waiting on its result. A scan
that finishes sooner but makes an interactive session stutter, or starves a
database of disk, has made a bad trade — so by default swinv steps out of the
way of everything else on the machine:

| | Default | `--fast` |
|---|---|---|
| CPU priority | `nice 10` (Linux) / background mode (Windows) | unchanged |
| I/O priority | idle class (Linux) / background mode (Windows) | unchanged |
| Cataloger workers | a quarter of the CPUs | every CPU |

Worker count is part of this and not merely a speed dial: it sets how deep an
I/O queue the process presents to the kernel, and a shallow queue is most of
what keeps a scan from making the rest of the machine feel slow.

The cost is real. Scanning `/usr` on an 8-core host took **41.6 s** by default
and **30.6 s** with `--fast` — about 36% slower for the politeness. Use
`--fast` when a person is waiting for the answer.

An explicit `--parallelism N` always wins over both modes, including a value
above the CPU count. That is a legitimate thing to ask for: a scan is usually
blocked on I/O rather than CPU, so oversubscribing can help on a host with fast
storage and nothing else to do.

Two honest limitations. On Linux, the idle I/O class is only honoured by the
**BFQ** scheduler; `mq-deadline` and `none`, which most distributions now
default to for NVMe, ignore it, and the kernel offers no way to ask in advance.
The nice value still applies. And neither mode addresses page-cache pressure:
reading a large tree evicts whatever the machine had cached, which swinv does
not currently mitigate on either platform.

### Diagnostics

| Flag | Default | Meaning |
|---|---|---|
| `--quiet` | `false` | Suppress stderr status output |
| `--verbose` | `false` | Per-stage timing to stderr |
| `--version` | — | Print version, commit, Syft version, OS/arch; exit 0 |

`--quiet` and `--verbose` are mutually exclusive. `--verbose` breaks the run
down by stage — symlink preflight, source construction, cataloging, conversion
— so a regression is attributable:

```console
$ swinv --root testdata/rootfs --out /tmp/inv --verbose
swinv: scanning testdata/rootfs ...
swinv: symlink preflight completed in 246µs (0 symlink(s) quarantined)
swinv: source constructed in 101µs (root /opt/code/swinv/testdata/rootfs, 0 exclusion patterns)
swinv: cataloging completed in 1.662s
swinv: conversion completed in 279µs (7 components)
swinv: found 7 components in 1663ms
```

---

## `--output-mode`

`--output-mode` only selects the default `--name` template. **An explicit
`--name` always wins**, whatever the mode.

| Mode | Template | Files across repeated runs |
|---|---|---|
| `dated` *(default)* | `{hostname}-{date}` | `web-01-20240309.json` — one file per day; a second run the same day replaces it |
| `overwrite` | `{hostname}` | `web-01.json` — one fixed file, replaced atomically every run |
| `timestamped` | `{hostname}-{datetime}` | `web-01-20240309T140506.000Z.json` — a brand-new file every run, kept forever |

One file is produced per requested `--format`, sharing the basename and
differing only in extension. With `--latest-symlink` (on by default) a
`{hostname}-latest.{ext}` symlink is pointed at the newest file of each format,
which is what makes `timestamped` mode practical to consume — and what gives
`--since` a stable path to read.

Placeholders available in `--name`:

| Placeholder | Expands to |
|---|---|
| `{hostname}` | `host.hostname` |
| `{machine_id}` | `host.machine_id` (`/etc/machine-id`) |
| `{date}` | Scan start, UTC, `20060102` |
| `{datetime}` | Scan start, UTC, `20060102T150405.000Z` |

Both the substituted values and the finished basename are **sanitised**: every
character outside `[A-Za-z0-9._-]` is dropped, so a hostile or merely odd
hostname cannot contain a `/` and escape `--out`. An empty hostname becomes
`unknown-host`; a template that sanitises down to nothing becomes `inventory`.

`--name` has no meaning with `--stdout` and passing both is a usage error.

## `--exclude`

Exclusion patterns are matched by Syft **relative to the scan root**, so a
pattern must begin with `./`, `*/`, or `**/`. This is a hard rule, not a
convention:

```sh
swinv --exclude './opt/build/**'     # a tree under the scan root
swinv --exclude '**/*.iso'           # a file at any depth
swinv --exclude '/opt/build/**'      # WRONG — absolute
```

An absolute pattern matches nothing at all, and anything else is rejected
outright when the source is constructed. `swinv` therefore validates every
pattern — its own defaults included — before scanning, and exits **2** with a
message that teaches the rule rather than letting Syft fail obscurely:

```console
$ swinv --exclude '/opt/build/**'
swinv: invalid exclusion pattern "/opt/build/**": exclusion patterns are relative
to the scan root and must start with "./", "*/", or "**/" (for example
"./var/cache/**" to skip a directory tree, or "**/*.iso" to skip a file anywhere)
```

`--exclude` is repeatable and **appends to** the defaults; it does not replace
them.

One caveat: the symlink preflight (which stops a single unreadable symlink from
aborting the entire scan) honours only `./`-anchored patterns. `*/` and `**/`
patterns are ignored there, so those paths are still lstat-ed during the
preflight walk. That is the safe direction to be wrong in — over-skipping would
let through exactly the symlink the pass exists to catch, and extra lstat calls
are cheap where a lost scan is not.

## `--hash`

Records a SHA-256 of each component's primary on-disk file in the `sha256`
field and CSV column. Off by default: it reads every such file **in full**,
which is substantial extra I/O on top of an already walk-dominated scan. Each
distinct file is read at most once, and the work is spread over `--parallelism`
workers.

**Files backing more than one component are deliberately not hashed.** Most deb
packages cite `/var/lib/dpkg/status` as their evidence. Digesting it would give
every package on the machine an identical hash *and* make all of them appear to
have changed whenever any single package changed — precisely backwards for
change detection. Only a file that uniquely backs one component gets a digest;
the number skipped is reported in `scan.warnings`.

Also skipped, silently: files over **512 MiB**, anything that is not a regular
file, and anything unreadable. A missing digest is never an error — a scan must
not fail because one file vanished mid-run.

The `sha256` CSV column exists whether or not `--hash` was passed, so the column
shape never varies with flags.

## `--since` and `--delta-only`

`--since PATH` reads a previous `swinv` JSON report and adds a `delta` block
listing `added`, `removed`, and `changed` components. Components are matched on
`(name, type)` — deliberately **not** on version — so an upgraded package reads
as one `changed` entry rather than a removal plus an unrelated addition.

By default the **full inventory is still written** alongside the delta, so the
file remains a complete, self-contained inventory. `--delta-only` drops the
unchanged components and emits just the diff, with each remaining component
tagged `added`, `removed`, or `changed` in its `change` field. `--delta-only`
without `--since` is a usage error.

Any schema version is accepted as a baseline: the delta only needs the
component list, and refusing an older report would break the flag exactly when
it is most wanted — after an upgrade.

**A `--delta-only` report is marked (`delta.delta_only`) and is refused as a
future baseline**, exit 2. Diffing against a diff would report every unchanged
package on the machine as newly added:

```console
$ swinv --since /var/lib/swinv/delta.json
swinv: --since: /var/lib/swinv/delta.json was written with --delta-only and holds
only changed components, so it cannot be used as a baseline; use a full inventory
report instead
```

A baseline that is unreadable, is not JSON, or has no `schema_version` is also
a usage error (exit 2).

Comparing against **another machine's** report is permitted but recorded in
`scan.warnings` — otherwise it silently looks as though the entire system was
replaced.

## `--max-memory`

Sets Go's **soft** memory limit for the process. Accepted forms:

| Form | Meaning |
|---|---|
| `512MiB`, `2GiB`, `1TiB` | IEC units |
| `512MB`, `2GB` | Same 1024-based multipliers — what people actually mean when sizing a process |
| `512M`, `2G` | Bare-letter shorthand, likewise 1024-based |
| `536870912` | A bare number is bytes |

Parsing is case-insensitive; suffixed forms accept a fractional value
(`1.5GiB`), a bare byte count must be an integer. The
value must be positive; anything else is a usage error.

Soft is the operative word. As the limit is approached the garbage collector
works proportionally harder, trading CPU for resident memory. If the genuinely
live data exceeds the limit, `swinv` still allocates rather than failing —
a truncated inventory would be worse than a larger process. It lowers peak RSS;
it cannot guarantee a ceiling.

It is nonetheless the single most effective one-flag change on a large host.
See [docs/PERFORMANCE.md](PERFORMANCE.md) for the measurements.

## `--catalogers`

The expression is passed straight to Syft's cataloger selection. Sets and
individual catalogers can be named, and `+`/`-` add to or remove from the
default selection:

```sh
swinv --catalogers os                 # OS package catalogers only
swinv --catalogers '+binary,-python'  # defaults, plus binary, minus python
```

With no `--catalogers`, the default selection is Syft's `installed` and
`directory` tags. The binary classifier, ELF-package, PE-package,
JVM-distribution, and Linux-kernel catalogers all carry the `directory` tag, so
a plain run already covers loose, unmanaged binaries.

**Honest note: this narrows parsing, not the filesystem walk.** Syft indexes
the entire filesystem when it builds the directory resolver, *before* cataloger
selection is applied, so `--catalogers os` is not a shortcut to a fast scan.
Use it to narrow the *output*, not to save time. The measured numbers and the
exclusion-based alternative (and why the obvious version of it is a trap) are
in [docs/PERFORMANCE.md](PERFORMANCE.md).

## `--stdout`

Writes the report to stdout instead of to files. It **requires exactly one
`--format`** — the default `json,csv` will be rejected — because two documents
interleaved on one stream are not parseable by anything.

```console
$ swinv --stdout
swinv: --stdout requires exactly one --format, got 2
```

All human-readable output — status lines, warnings, errors — goes to **stderr**
in every mode, so stdout carries nothing but the report and stays safe to pipe.
`--out`, `--latest-symlink`, and the `--output-mode` naming are all irrelevant
under `--stdout`; `--name` is rejected outright.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; a complete inventory was written |
| 1 | Partial success; output was written but `scan.incomplete` is `true` |
| 2 | Usage error: bad flag, positional argument, unknown `--format` or `--output-mode`, bad exclusion pattern, conflicting options, unusable `--since` baseline |
| 3 | Fatal: could not construct the source, could not create `--out`, could not write output, or `--require-host-id` with no machine ID |
| 4 | Timeout: `--timeout` exceeded |

**A single failing cataloger never aborts the run.** The failure is recorded in
`scan.warnings`, `scan.incomplete` is set to `true`, the output is written
anyway, and the exit code is 1. An inventory missing one ecosystem is far more
useful than no inventory, and the JSON says plainly which one it is.

Exit 4 is distinguished from exit 3 because context failures are wrapped such
that `errors.Is(err, context.DeadlineExceeded)` still holds on the returned
error.

Running as a non-root user is fully supported and is **not** an error. Such a
run misses root-only paths and the DMI serial and UUID; `scan.ran_as_root` is
`false`, a warning is recorded, and the exit code is unaffected.

`swinv -h` prints usage to stderr and exits 0 — asking for help is not an error. `swinv --version` prints to
stdout and exits 0.

## Environment

| Variable | Used by | Effect |
|---|---|---|
| `SWINV_UPDATE_GOLDEN=1` | `make golden` only | Rewrites the checked-in golden JSON and CSV in `testdata/golden` from a scan of `testdata/rootfs` |

No environment variable configures a normal run. Everything is a flag.

## Recipes

One-shot inventory to a temp directory, JSON only, nothing left behind:

```sh
swinv --out /tmp/inv --format json --output-mode overwrite
```

OS packages only, for a smaller file (not a faster scan — see
[docs/PERFORMANCE.md](PERFORMANCE.md)):

```sh
swinv --catalogers os --out /var/lib/swinv
```

Pipe CycloneDX straight to a vulnerability scanner, with no file on disk:

```sh
swinv --format cyclonedx-json --stdout > sbom.json
grype sbom:sbom.json
```

Inspect the inventory interactively without writing anything:

```sh
swinv --format json --stdout | jq -r '.components[] | "\(.type)\t\(.name)\t\(.version)"'
```

The daily-timer pattern: keep every run, and diff each one against the previous
via the `-latest` symlink. Read the symlink *before* this run overwrites it.

```sh
swinv --out /var/lib/swinv \
      --output-mode timestamped \
      --since "/var/lib/swinv/*-latest.json"
```

Memory-constrained host — the lowest peak RSS measured, at roughly twice the
wall time:

```sh
swinv --max-memory 768MiB --parallelism 1 --out /var/lib/swinv
```

A workstation, including home directories and skipping a large build tree, with
content digests for change detection:

```sh
swinv --include-home --exclude './opt/build/**' --hash --out /var/lib/swinv
```

Just the diff, for a change feed rather than an inventory (remember the
resulting file cannot serve as the next baseline):

```sh
swinv --since /var/lib/swinv/web-01-latest.json --delta-only \
      --format json --out /var/lib/swinv --name web-01-changes
```
