# swinv flag reference

Every command-line flag, its default, its exact behaviour, and the exit codes.
Part of the [swinv](../README.md) documentation.

## Synopsis

```
swinv [flags]
```

`swinv` takes **no positional arguments** - passing one is a usage error. It
scans the machine it runs on, enumerates installed software, and writes the
result to local files. Nothing is sent over the network unless `--transmit`
says so, and even then the files are still written.

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

`--require-host-id` exits **3**, not 2 - it is a fatal runtime condition, not a
usage problem.

### Output

| Flag | Default | Meaning |
|---|---|---|
| `--out DIR` | `/var/lib/swinv` | Output directory; created `0755` if missing, files written `0644` |
| `--output-mode MODE` | `timestamped` | `timestamped`, `dated`, or `overwrite` - see below |
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

Every file is written atomically - temp file in the same directory, `fsync`,
`rename`, `fsync` of the directory - so a collector can never read a
half-written inventory. The `-latest` symlinks are replaced atomically too, and
a symlink that would collide with the output file itself is skipped rather than
overwriting it. A failure to update a symlink is a warning on stderr, not a
failed run: it is not worth discarding a good inventory over.

### Exclusions

| Flag | Default | Meaning |
|---|---|---|
| `--exclude GLOB` | *(none)* | Additional exclusion pattern; repeatable, appended to the defaults |
| `--no-auto-exclude-mounts` | `false` | Do not auto-exclude non-local filesystems |

The final exclusion list - defaults, mount-derived exclusions, your patterns,
and any symlinks quarantined by the preflight - is always recorded in
`scan.excluded`.

### Services

| Flag | Default | Meaning |
|---|---|---|
| `--no-services` | `false` | Do not report what is listening on the network |
| `--no-containers` | `false` | Do not look inside containers for what they run |
| `--no-service-command` | `false` | Omit each service's command line from the report |

Both platforms. On Linux the sockets come from `/proc`; on Windows from
`iphlpapi`, which returns the socket tables with an owning pid already
attached.

Services are collected by default because the question they answer - which of
the installed software is actually serving, and which serving software nothing
installed accounts for - is not answerable from a package list. The cost is
milliseconds against a scan that costs minutes.

Two reasons to turn something off:

- **`--no-service-command`** drops the `command` field and keeps everything
  else. Command lines are where secrets end up - a `--password` on a daemon's
  ExecStart, a connection string with credentials in it - and an inventory file
  is usually copied somewhere with a different audience. See
  [SECURITY.md](../SECURITY.md).
- **`--no-services`** skips the section entirely, including reading
  `/proc/<pid>/fd`.
- **`--no-containers`** keeps the host services and the exposure list but stops
  swinv identifying containers at all - including its one conversation with a
  daemon, the local container runtime. The cost is the identity of everything
  behind a published port, and of every stopped container: the answer comes
  from the container's own package database, reached either through
  `/proc/<pid>/root` (Linux, running) or through the runtime's archive
  endpoint (stopped containers, and everything on Windows).

Unprivileged, this degrades rather than fails: `/proc/net` is world-readable so
the ports are still reported, but attributing a socket to a process needs to
read that process's open files, which on a server is nearly all of them. The
count that could not be attributed becomes one aggregate entry and a warning,
not silence.

See [docs/SERVER-ROLES.md](SERVER-ROLES.md) for the design, and
[docs/OUTPUT.md](OUTPUT.md#services) for the schema.

### Change detection

| Flag | Default | Meaning |
|---|---|---|
| `--hash` | `false` | Record a SHA-256 of each component's primary file |
| `--elf-scope MODE` | `listening` | Whose shared-library links to read: `listening`, `all`, `off` |
| `--elf-symbols` | `false` | Record imported symbol lists, not only counts |
| `--ndjson-include LIST` | *(none)* | NDJSON also carries `exposure`, `containers`, `links`, or `all` |
| `--heartbeat` | `false` | NDJSON: a digest every scan, components only when it changes |
| `--force-full` | `false` | With `--heartbeat`, send the components anyway |
| `--full-interval DUR` | `24h` | With `--heartbeat`, send in full at least this often (`0` = never force one) |
| `--since PATH` | *(none)* | Compare against a previous swinv JSON report and emit a delta |
| `--delta-only` | `false` | With `--since`, emit only the changed components |

### `--ndjson-include`

NDJSON carries one component per line. `exposure[]`, `containers[]` and the
shared-library links are in the JSON document and the CSV sidecars, but not in
the one output shape built for streaming - so a forwarder tailing the `.ndjson`
sees none of them.

```sh
swinv --out /var/lib/swinv --format ndjson --ndjson-include all
```

The list takes `exposure`, `containers`, `links`, `config`, or `all`.

Off by default because every line was a component before this existed. Each
extra record carries a `record_type` an older consumer can skip; a line without
one is a component.

`exposure` is denormalised to one record per (port, package), so a finding
joins on the package without unpacking an array - and a port with nothing
attributed still produces a record, because that is a gap in what can be seen
rather than a port that is safe. `containers` includes stopped ones, whose
vulnerabilities are latent rather than absent.

Both are small - on a 17-container host, 46 exposure and 16 container records
against 2,715 components - so they are emitted even on an unchanged
`--heartbeat` scan. What is listening changes while installed software does
not.

`links` is one record per (binary, library it loads), joined to the owning
package. Unlike the other two it is derived from the installed software, so an
unchanged heartbeat scan suppresses link records along with the components -
a few hundred at the default `--elf-scope`, ~36,000 with `--elf-scope all`,
resent on every scan, would undo what the heartbeat saves.

See [docs/OUTPUT.md](OUTPUT.md#the-heartbeat) for the record shapes.

### `--heartbeat`

Every scan restates the whole inventory. That is the right shape for
correctness - a package that disappears is genuinely gone rather than merely
unmentioned - and the wrong shape for volume: 5,000 hosts averaging 14,000
components scanned hourly is over a billion NDJSON records a day, nearly all
identical to the day before.

`--heartbeat` puts one small record at the head of the NDJSON stream carrying
a digest of the inventory, and omits the component records entirely when that
digest matches the previous scan on this host.

```sh
swinv --out /var/lib/swinv --format ndjson --heartbeat
```

**Only NDJSON is affected.** JSON, CSV and CycloneDX carry the full inventory
every time. A CSV with no rows would be a false statement about the machine.

**Not a delta.** When anything changes, the *whole* list is sent again. A delta
cannot express a removal, and "this package is no longer installed" is the fact
that decides whether a vulnerability is fixed or merely unreported.

A full list is also sent when there is no previous record for the host, when
the state file cannot be read, on `--force-full`, and whenever
`--full-interval` has elapsed - so a digest collision or a hand-edited state
file cannot hide a change indefinitely. Any doubt resolves toward sending too
much.

This is the only thing swinv remembers between runs: `.swinv-heartbeat.json`
in the output directory, one digest per hostname. Delete it and the next scan
sends everything, which costs one redundant send and nothing else.

See [docs/OUTPUT.md](OUTPUT.md#the-heartbeat) for the record shape and what the
digest is built from.

### Resources

| Flag | Default | Meaning |
|---|---|---|
| `--usn-probe` | `false` | Windows only, experimental: enumerate the MFT and report what it finds |
| `--volumes SPEC` | *(C:)* | Windows only: volumes to enumerate, e.g. `D:` or `D:,E:` |
| `--debug-stacks-after DUR` | `0` (never) | If the scan is still running after this long, write every goroutine stack to a file and carry on |
| `--fast` | `false` | Scan at normal scheduling priority and full parallelism |
| `--max-memory SIZE` | *(unlimited)* | Soft memory limit, e.g. `1536MiB` |
| `--parallelism N` | `0` | Cataloger parallelism; `0` chooses automatically - see below |
| `--timeout DURATION` | `30m` | Whole-run deadline (Go duration syntax: `90s`, `10m`, `2h`) |

`--parallelism` must not be negative and `--timeout` must be positive;
either is a usage error.

`--timeout` is enforced two ways, and this matters on Linux as much as on
Windows. Syft's directory indexer takes no context parameter at all - neither
`NewFromDirectory` nor `buildIndex` accepts one - so the filesystem walk cannot
be cancelled on any platform. Measured on Linux: a `--timeout 3s` scan of a
300,000-file tree took **10.8 seconds** to exit, because the walk had to finish
first. The overrun grows with the tree, and on a network filesystem or a cold
disk it can be far worse. Normally the deadline cancels the scan
cooperatively and swinv exits 4. But Syft indexes the filesystem with
`filepath.Walk`, which takes no context, so a scan wedged in indexing never
reaches a cancellation check - a `--timeout 5m` run on a Windows host was
observed still going at 5m30s. A watchdog therefore terminates the process if
the deadline is exceeded by more than ten seconds. Reports are written by
staging to a temp file and renaming, so a terminated run may leave a `.tmp-*`
file beside the target but can never leave a half-written report in its place.

#### `--usn-probe` and `--volumes` (Windows, experimental)

`--usn-probe` enumerates the NTFS Master File Table through
`FSCTL_ENUM_USN_DATA` and reports what it found. It is a measuring instrument,
not a scan: no inventory is produced and no file is opened. The Windows
collector described in [docs/WINDOWS.md](WINDOWS.md) does not exist yet, and
this exercises the one piece of it that does.

It needs an elevated process and an NTFS volume, and says which is missing when
it refuses. On anything other than Windows it exits 2 immediately.

```console
> swinv --usn-probe --volumes D:,E:
swinv: D: 412883 MFT records in 14.2s
swinv: D: 51204 directories, 38119 executables kept, 0 paths unresolved
swinv: D: kept 9.2% -- the other 90.8% were never opened
swinv:        18422  D:\Program Files\Adobe
swinv:         9110  D:\Program Files\Siemens
...
```

`--volumes` **replaces** the default rather than extending it: `--volumes D:`
enumerates D: and does **not** enumerate C:. An operator who names volumes has
said which ones they want, and silently adding the system drive would produce a
far longer run than they asked for. Duplicates are dropped in first-mentioned
order, so a volume is never enumerated twice.

Passing `--volumes` without `--usn-probe` is a usage error today, because the
collector it will eventually configure does not exist. It refuses rather than
being ignored, so that nobody believes they have restricted a scan when they
have not.

`--help` and `-h` print to **stdout** and exit 0, so `swinv --help | less` and
`swinv --help > notes.txt` both work. Usage errors print to stderr and exit 2,
and deliberately do *not* print the help page: an operator who mistyped a flag
needs the one line naming it, not sixty lines of everything else.

The help page lists only flags that do something on the platform it was built
for. The others stay registered, so `swinv --usn-probe` on Linux answers "that
only works on Windows" rather than "flag provided but not defined" - a runbook
pasted onto the wrong platform gets an explanation instead of a parse error.

On Windows, the first `--full-scan` on a machine is much slower than the ones
after it - measured at 14m21s and then 1 second, for the same command doing
identical work. Antivirus scans each executable the first time it is opened and
caches the result, so a scheduled task pays the cost once. See
[docs/WINDOWS.md](WINDOWS.md#measured-the-first---full-scan-is-slow-and-the-rest-are-not).

`--quiet` and `--debug-stacks-after` combine, which is the case that matters:
a scheduled task runs silent, and when one appears to hang you want a dump
without also turning the logging back on. Under `--quiet` the dump file is still
written to the output directory as `swinv-stacks-<timestamp>.txt`; only the line
announcing it is suppressed. `--quiet` is a promise about output, not about work.

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
dumping afterwards would be too late - by then the deadline has unwound the
worker goroutines and the frame that explains the stall is gone. If the output
directory is not writable the dump falls back to the temp directory.

#### swinv is deliberately slow by default

An inventory collector is background maintenance. It runs unattended, on a
timer, on machines doing real work, and nobody is waiting on its result. A scan
that finishes sooner but makes an interactive session stutter, or starves a
database of disk, has made a bad trade - so by default swinv steps out of the
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
and **30.6 s** with `--fast` - about 36% slower for the politeness. Use
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
| `--version` | - | Print version, commit, Syft version, OS/arch; exit 0 |

`--quiet` and `--verbose` are mutually exclusive. `--verbose` breaks the run
down by stage - symlink preflight, source construction, cataloging, conversion
- so a regression is attributable:

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
| `dated` | `{hostname}-{date}` | `web-01-20240309.json` - one file per day; a second run the same day replaces it |
| `overwrite` | `{hostname}` | `web-01.json` - one fixed file, replaced atomically every run |
| `timestamped` | `{hostname}-{datetime}` | `web-01-20240309T140506.000Z.json` - a brand-new file every run, kept forever |

The default changed from `dated` to `timestamped`. A report records what was
installed at a moment, and under `dated` a second run on the same day silently
replaced the first - so an operator investigating a change had one data point
where they expected two. Keeping every run costs a file per run; losing one
costs the answer.

Files accumulate under `timestamped`, and nothing prunes them. The
`{hostname}-latest.{ext}` pointer always names the newest, so a consumer reading
that is unaffected. If unbounded growth is a problem, `--output-mode dated` is
still there.

One file is produced per requested `--format`, sharing the basename and
differing only in extension. With `--latest-symlink` (on by default) a
`{hostname}-latest.{ext}` symlink is pointed at the newest file of each format,
which is what makes `timestamped` mode practical to consume - and what gives
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
swinv --exclude '/opt/build/**'      # WRONG - absolute
```

An absolute pattern matches nothing at all, and anything else is rejected
outright when the source is constructed. `swinv` therefore validates every
pattern - its own defaults included - before scanning, and exits **2** with a
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
preflight walk. That is the safe direction to be wrong in - over-skipping would
let through exactly the symlink the pass exists to catch, and extra lstat calls
are cheap where a lost scan is not.

## `--config-scope`

What configuration surface to read: `standard` (default), `all`, or `off`.

The standard scope is the cheap, high-signal set, all of it local reads: cron
(`/etc/crontab`, `/etc/cron.d`, the periodic directories, per-user spools),
systemd timers and services (with `/etc` shadowing `/run` shadowing
`/usr/lib`, the way systemd resolves them), and SUID/SGID binaries under the
standard binary directories - the same population the ELF probe walks. On
Windows: Scheduled Tasks (read from the task store's XML directly, no COM)
and the machine Run/RunOnce keys plus the all-users Startup folder. `all`
extends the SUID walk to the whole filesystem, which is what finds the one
dropped in `/var/tmp` and costs a filesystem walk to do it.

Each entry's executable is joined to the package that installed it through
the same ownership probe the listening services use, so `purl` is filled
where a package owns the program and conspicuously absent where nothing does.
`--no-service-command` drops the command lines here too - a cron line carries
credentials as often as a service command line does - while keeping the
executable path, which is joinable and carries no secrets.

See [docs/OUTPUT.md](OUTPUT.md) for the record shape and the ATT&CK framing.

## `--hash`

Records a SHA-256 of each component's primary on-disk file in the `sha256`
field and CSV column. Off by default: it reads every such file **in full**,
which is substantial extra I/O on top of an already walk-dominated scan. Each
distinct file is read at most once, and the work is spread over `--parallelism`
workers.

**Files backing more than one component are deliberately not hashed.** Most deb
packages cite `/var/lib/dpkg/status` as their evidence. Digesting it would give
every package on the machine an identical hash *and* make all of them appear to
have changed whenever any single package changed - precisely backwards for
change detection. Only a file that uniquely backs one component gets a digest;
the number skipped is reported in `scan.warnings`.

Also skipped, silently: files over **512 MiB**, anything that is not a regular
file, and anything unreadable. A missing digest is never an error - a scan must
not fail because one file vanished mid-run.

The `sha256` CSV column exists whether or not `--hash` was passed, so the column
shape never varies with flags.

## `--since` and `--delta-only`

`--since PATH` reads a previous `swinv` JSON report and adds a `delta` block
listing `added`, `removed`, and `changed` components. Components are matched on
`(name, type)` - deliberately **not** on version - so an upgraded package reads
as one `changed` entry rather than a removal plus an unrelated addition.

By default the **full inventory is still written** alongside the delta, so the
file remains a complete, self-contained inventory. `--delta-only` drops the
unchanged components and emits just the diff, with each remaining component
tagged `added`, `removed`, or `changed` in its `change` field. `--delta-only`
without `--since` is a usage error.

Any schema version is accepted as a baseline: the delta only needs the
component list, and refusing an older report would break the flag exactly when
it is most wanted - after an upgrade.

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
`scan.warnings` - otherwise it silently looks as though the entire system was
replaced.

## `--max-memory`

Sets Go's **soft** memory limit for the process. Accepted forms:

| Form | Meaning |
|---|---|
| `512MiB`, `2GiB`, `1TiB` | IEC units |
| `512MB`, `2GB` | Same 1024-based multipliers - what people actually mean when sizing a process |
| `512M`, `2G` | Bare-letter shorthand, likewise 1024-based |
| `536870912` | A bare number is bytes |

Parsing is case-insensitive; suffixed forms accept a fractional value
(`1.5GiB`), a bare byte count must be an integer. The
value must be positive; anything else is a usage error.

Soft is the operative word. As the limit is approached the garbage collector
works proportionally harder, trading CPU for resident memory. If the genuinely
live data exceeds the limit, `swinv` still allocates rather than failing -
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
`--format`** - the default `json,csv` will be rejected - because two documents
interleaved on one stream are not parseable by anything.

```console
$ swinv --stdout
swinv: --stdout requires exactly one --format, got 2
```

All human-readable output - status lines, warnings, errors - goes to **stderr**
in every mode, so stdout carries nothing but the report and stays safe to pipe.
`--out`, `--latest-symlink`, and the `--output-mode` naming are all irrelevant
under `--stdout`; `--name` is rejected outright.

`--stdout` writes one stream, so it has no services sidecar: `--stdout --format
csv` gives the components alone. `--stdout --format json` carries the whole
report, `services[]` included.

### Transmitting to a server

| Flag | Default | Meaning |
|---|---|---|
| `--transmit URL` | *(off)* | Also POST this scan to a Riskability server, e.g. `https://riskability.example/api/v1`. The report files under `--out` are written exactly as they would be without it. |
| `--transmit-token-file PATH` | *(none)* | Read the bearer token from this file. `$SWINV_TRANSMIT_TOKEN` is the alternative. |
| `--transmit-cert PATH` | *(none)* | Client certificate (PEM). |
| `--transmit-key PATH` | *(none)* | Private key (PEM) for `--transmit-cert`. |
| `--transmit-ca PATH` | *(none)* | CA bundle (PEM) to verify the server against. |
| `--transmit-insecure` | `false` | Do not verify the server's certificate. Prints a warning on every run, `--quiet` included. |
| `--transmit-batch-lines N` | `2000` | Maximum records per request. |
| `--transmit-batch-bytes SIZE` | `1MiB` | Maximum uncompressed bytes per request. |
| `--transmit-attempts N` | `5` | Attempts per request including the first, with exponential backoff and jitter. |
| `--transmit-timeout DURATION` | `60s` | Deadline for one request, not for the whole upload. |
| `--transmit-key-passphrase-file PATH` | *(none)* | Passphrase for an encrypted `--transmit-key`. A systemd credential or `$SWINV_TRANSMIT_KEY_PASSPHRASE` also works; see below. |
| `--transmit-pin SPKI` | *(none)* | Verify the server by its public key: base64 SHA-256 of the SubjectPublicKeyInfo. Repeatable. |
| `--transmit-tls-min VERSION` | `1.2` | Minimum TLS version, `1.2` or `1.3`. There is no spelling that lowers the floor. |
| `--transmit-check` | `false` | Validate endpoint, auth, TLS and clock, then exit. No scan, nothing sent. |
| `--transmit-only` | `false` | Send the spooled backlog and exit. No scan. |
| `--transmit-from PATH` | *(none)* | Send this NDJSON file and exit. Refused when its manifest disagrees with its contents. |
| `--transmit-rate-limit SIZE/s` | *(unlimited)* | Cap upload throughput, e.g. `256KiB`, for metered links. |
| `--transmit-compress MODE` | `auto` | `auto`, `always`, or `never`. |
| `--transmit-require-complete` | `true` | Do not transmit a scan whose sources failed; `=false` sends anyway. |

**There is no `--transmit-token` flag.** Every process on the machine can read
`/proc/<pid>/cmdline`, so a token on the command line is a token handed to
every local user. Use the file or the environment variable.

**Both auth mechanisms are supported, and both may be used at once.** Some
estates will not distribute bearer tokens; some cannot run an internal CA.

**File output stays first class.** `--transmit` adds a destination, it does not
replace one. Air-gapped sites are the likeliest audience for this product and
they move files by means they already trust. Pair `--transmit` with
`--output-mode overwrite` if a growing directory of timestamped files is not
wanted.

**Batching.** A batch ends when either limit trips. Line count alone is not
enough: a host with large attribute maps puts 2,000 lines well past any sane
request body, and a 4 MB scan in one request is what this exists to prevent.
Bodies are gzipped (about 9:1 on this data).

**Idempotency and resumption.** Every scan gets a `scan_id`, sent with every
batch, and the server dedupes on `(scan_id, batch_index)` - so a retry after a
timeout cannot double-count a host. The NDJSON is spooled to
`<out>/.swinv-spool/` before the first request and removed only once the server
has accepted and reconciled it. A collector that dies at batch nine is finished
by the next run rather than rescanning; a server that restarts mid-scan costs a
few duplicate batches rather than the whole upload. The resume point comes from
`GET .../status`, because the server is the only party that knows what it
stored.

**Retries.** 5xx and network failures are retried; 4xx are not, except `429`,
which is the one 4xx that says "later" rather than "no". A permanent failure
says so on stderr and leaves the spool in place.

**Proxies.** `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` are honoured.

**Encrypted client keys.** `--transmit-key` accepts a PKCS#8 encrypted key -
the `BEGIN ENCRYPTED PRIVATE KEY` that `openssl pkcs8 -topk8 -v2 aes-256-cbc`
writes - decrypted in-process with no dependency added. The legacy RFC 1423
format (`Proc-Type: 4,ENCRYPTED` in the PEM) is refused by name with the
command that re-wraps it: its MD5-based construction was deprecated out of
Go's standard library and should not ride into a new deployment. The
passphrase comes from, in order of preference, each logged when used:

1. **A systemd credential named `swinv.key-passphrase`** - the packaged unit's
   `LoadCredentialEncrypted=` seals it to the TPM on modern hosts. This is the
   right arrangement for a collector that runs unattended from a timer.
2. **`--transmit-key-passphrase-file`**, refused unless the file is mode
   `0600`: an encrypted key whose passphrase sits world-readable next to it is
   theatre.
3. **`$SWINV_TRANSMIT_KEY_PASSPHRASE`**, the weakest option, documented as
   such.

There is no interactive prompt on purpose. This runs from a timer, and a flag
that can block forever on a TTY that is not there is a hang, not a feature.

**Pinning.** `--transmit-pin` verifies the server by public key instead of by
chain, for the site that cannot get its CA into the trust store and should not
be pushed to `--transmit-insecure`. Any certificate in the presented chain may
match, so pinning an internal CA's key survives leaf rotation; giving the flag
twice makes a key rotation two pins for a while rather than a flag day. The
pin is the base64 SHA-256 of the SubjectPublicKeyInfo:

```sh
openssl x509 -in server.crt -pubkey -noout \
  | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

A mismatch refuses the connection and prints the pins the server presented,
so a first deployment is: run `--transmit-check` once, copy the pin from the
output, run again. `--transmit-pin` and `--transmit-insecure` together are an
error, not a precedence rule.

**Preflight.** `--transmit-check` contacts the server, authenticates, and
prints one greppable line per check - reachable, TLS version and cipher,
certificate expiry and observed pin, credentials accepted or rejected, proxy
in use, clock skew - without scanning or sending anything. Non-zero exit on
any failure. This is the first step of the runbook and a natural `postinst`
check; without it, diagnosing a bad token means running a full scan to find
out.

**Sending without scanning.** `--transmit-only` flushes the spooled backlog -
the server was down for a day, the spool holds the scans, and no host should
need a fresh 30-minute scan to deliver them. `--transmit-from FILE` sends one
existing NDJSON file, for relay hosts (a segment with no route to the server
writes files; a host that can reach it sends them) and for backfilling a new
server. The file must carry a manifest whose counts agree with its contents;
a file already known to be wrong is refused before a byte leaves the machine.

**Do not let a degraded scan become the fleet's truth.**
`--transmit-require-complete` (on by default) withholds the upload when an
inventory source failed. A scan where the dpkg cataloger failed produces a
valid file with a plausible component count, and once it is on the server it
*is* the host's inventory: the matcher correctly reports few findings because
few packages were assessed, and every layer succeeds while the host goes
silently unassessed. The refusal happens at the host, where the exit code (5)
is visible, instead of in a reconciliation report nobody reads. The files on
disk are still written; `=false` restores "send what you have".

**`--transmit` implies the manifest.** The server opens a scan with the
heartbeat record and reconciles the close against its counts, so the record is
emitted whether or not `--heartbeat` was given. `--heartbeat` still controls
whether unchanged inventories suppress their component records.

`--transmit` is refused with `--offline` (which promises no network activity at
all), with `--stdout` (there is nowhere to spool), and with `--delta-only` (the
server reconciles against a full inventory, and a delta is not one). To send
exposure and container records as well as components, add `--ndjson-include
all`; without it those counts are legitimately zero.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; a complete inventory was written |
| 1 | Partial success; output was written but `scan.incomplete` is `true` |
| 2 | Usage error: bad flag, positional argument, unknown `--format` or `--output-mode`, bad exclusion pattern, conflicting options, unusable `--since` baseline |
| 3 | Fatal: could not construct the source, could not create `--out`, could not write output, or `--require-host-id` with no machine ID |
| 4 | Timeout: `--timeout` exceeded |
| 5 | A source could not be enumerated: a package database is present on this host and could not be read |
| 6 | Transmission did not complete, or completed and did not reconcile |

**Exit 5 is the refusal to be quietly useless.** A package database that exists
and cannot be read produces a small, valid, perfectly healthy-looking
inventory - and fifteen components from a host with four thousand is
indistinguishable from a minimal machine. The report is still written, and
`scan.sources` names the source and the reason; the exit code is what a timer
checks. It outranks 1 and 6, so a run that both lost a source and failed to
transmit reports the source.

Exit 5 is not raised when the database is absent (that is a fact about the
host, reported as `skipped`), when it is present and zero bytes, or when
`--catalogers` deliberately excluded the source.

**Exit 6 never destroys the local copy.** The report files are written before
anything is uploaded, and the spooled scan is kept for the next run.

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

`swinv -h` prints usage to stderr and exits 0 - asking for help is not an error. `swinv --version` prints to
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

OS packages only, for a smaller file (not a faster scan - see
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

Memory-constrained host - the lowest peak RSS measured, at roughly twice the
wall time:

```sh
swinv --max-memory 768MiB --parallelism 1 --out /var/lib/swinv
```

A workstation, including home directories and skipping a large build tree, with
content digests for change detection:

```sh
swinv --include-home --exclude './opt/build/**' --hash --out /var/lib/swinv
```

What is exposed at the network edge, with the software behind each port -
including software running inside containers:

```sh
sudo swinv --out /var/lib/swinv --format json,csv
jq -r '.exposure[] | select(.bind_scope != "loopback")
       | [.bind_scope, "\(.address):\(.port)/\(.protocol)", (.components|join(","))]
       | @tsv' /var/lib/swinv/*-latest.json
```

Everything a container is running, whether or not it is published:

```sh
jq -r '.containers[] | .name as $n | .os_id as $os | .services[]
       | "\($n)\t\($os)\t\(.executable)\t\((.components // ["-"])|join(","))"' \
   /var/lib/swinv/*-latest.json
```

Before trusting a small exposure list, read what the scan could not see:

```sh
jq -r '.scan.exposure_blind_spots[]' /var/lib/swinv/*-latest.json
```

On a Kubernetes node, or a host with `userland-proxy` disabled, that list is
the difference between "nothing is exposed" and "the exposure could not be
observed".

What is listening, and what installed it - the reason to run this as root:

```sh
sudo swinv --out /var/lib/swinv --format json,csv
jq -r '.services[] | [.confidence, (.endpoints|join(",")), (.components|join(","))] | @tsv' \
   /var/lib/swinv/*-latest.json
```

Serving software that no package manager installed, which is the finding a
package inventory cannot produce on its own:

```sh
jq -r '.services[] | select(.confidence == "medium") | "\(.endpoints[0])\t\(.executable)"' \
   /var/lib/swinv/*-latest.json
```

An inventory destined for somewhere with a wider audience, without the command
lines that carry secrets:

```sh
swinv --no-service-command --out /var/lib/swinv --perm 0640
```

Everything a streaming consumer needs - components, what is listening, and the
containers - in one file:

```sh
swinv --out /var/lib/swinv --format ndjson --ndjson-include all
```

Hourly scans into a log pipeline, sending components only when they change:

```sh
swinv --out /var/lib/swinv --format ndjson --heartbeat --ndjson-include all \
      --output-mode overwrite
```

Just the diff, for a change feed rather than an inventory (remember the
resulting file cannot serve as the next baseline):

```sh
swinv --since /var/lib/swinv/web-01-latest.json --delta-only \
      --format json --out /var/lib/swinv --name web-01-changes
```
