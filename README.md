# `swinv`

[![CI](https://github.com/chaugan/swinv/actions/workflows/ci.yml/badge.svg)](https://github.com/chaugan/swinv/actions/workflows/ci.yml)
[![Go](https://img.shields.io/github/go-mod/go-version/chaugan/swinv)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Local software inventory for Linux: one static binary, files on disk, nothing
leaves the host.**

`swinv` scans the machine it runs on and records every piece of installed
software it can find — OS packages, language packages, and loose binaries that no
package manager ever installed — then writes the result to local JSON and CSV
files.

There is no server, no daemon and no database, and **no inventory data ever
leaves the machine**. Collecting the files afterwards is deliberately your job:
`rsync`, Ansible, a log shipper, or `scp`.

The one piece of network activity is an optional reverse-DNS lookup used to
fill in the host's FQDN — ordinary name resolution against your configured
resolver, carrying no inventory data. `--offline` turns it off, at which point
the run performs no network activity at all.

Detection comes from [Syft](https://github.com/anchore/syft), imported as a
library, which gives roughly 40 package ecosystems and a binary classifier
in-process with no subprocess overhead.

---

## Quickstart

```sh
sudo dpkg -i swinv_0.1.0-1_amd64.deb   # or: sudo rpm -i swinv-0.1.0-1.x86_64.rpm
swinv --out /tmp/inv                   # scan /, write JSON + CSV
```

No package? The binary is static and has no dependencies, so
`install -m0755 swinv-v0.1.0-linux-amd64 /usr/bin/swinv` is equally fine, as is
`make build` from a clone.

That writes dated files plus `-latest` symlinks:

```console
/tmp/inv/web-01-20260819.json
/tmp/inv/web-01-20260819.csv
/tmp/inv/web-01-latest.json -> web-01-20260819.json
/tmp/inv/web-01-latest.csv  -> web-01-20260819.csv
```

Look at what came out, pipe a single format, or ask what changed since last time:

```sh
jq '.components | length' /tmp/inv/web-01-latest.json
swinv --format json --stdout | jq '.components[0]'
swinv --since /var/lib/swinv/*-latest.json      # added/removed/changed
```

To run it daily across a fleet, install the `.deb` or `.rpm` and enable the
timer — see [Install](#install).

Running as root finds more (root-only paths, DMI serials). Running unprivileged
is fully supported, never an error, and records a warning saying what it missed.

### What comes out

Everything below is real output, reproducible from a clone — the repository ships
a small fixture filesystem so you can see the shape before scanning anything.
Only the hostname has been substituted:

```console
$ ./bin/swinv --root testdata/rootfs --out /tmp/ex
swinv: scanning testdata/rootfs ...
swinv: found 7 components in 1383ms
swinv: wrote /tmp/ex/web-01-20260819.json
swinv: wrote /tmp/ex/web-01-20260819.csv
```

Status goes to stderr; only `--stdout` data goes to stdout. The JSON:

```jsonc
{
  "schema_version": "1.1",
  "tool": { "name": "swinv", "version": "dev", "syft_version": "v1.51.0" },
  "host": {
    "hostname": "web-01",
    "os_id": "debian",
    "os_version_id": "12",
    "os_pretty_name": "Debian GNU/Linux 12 (bookworm)",
    "architecture": "amd64"
  },
  "scan": {
    "started_at": "2026-08-19T11:49:06.078072995Z",
    "finished_at": "2026-08-19T11:49:07.461714314Z",
    "duration_ms": 1383,
    "root": "testdata/rootfs",
    "catalogers": ["installed", "directory"],
    "ran_as_root": false,
    "incomplete": false,
    "warnings": [
      "not running as root: root-only paths and DMI identifiers were skipped"
    ]
  },
  "components": [
    {
      "name": "bash",
      "version": "5.2.15-2+b7",
      "type": "deb",
      "purl": "pkg:deb/debian/bash@5.2.15-2%2Bb7?arch=amd64&distro=debian-12",
      "cpes": ["cpe:2.3:a:bash:bash:5.2.15-2\\+b7:*:*:*:*:*:*:*"],
      "locations": ["/var/lib/dpkg/status"],
      "found_by": "dpkg-db-cataloger"
    },
    {
      "name": "flask",
      "version": "3.0.0",
      "type": "python",
      "language": "python",
      "purl": "pkg:pypi/flask@3.0.0",
      "cpes": ["cpe:2.3:a:flask:flask:3.0.0:*:*:*:*:*:*:*"],
      "licenses": ["BSD-3-Clause"],
      "locations": [
        "/usr/lib/python3/dist-packages/flask-3.0.0.dist-info/METADATA",
        "/usr/lib/python3/dist-packages/flask-3.0.0.dist-info/RECORD"
      ],
      "found_by": "python-installed-package-cataloger"
    }
  ]
}
```

`scan.warnings` and `scan.excluded` always record what was skipped and why, so a
consumer can tell a thin inventory from a complete one.

The CSV is the same data, one row per component, with host identity repeated on
every row so files concatenate cleanly across a fleet. Rows are wide, so here is
one folded onto its 17 columns:

```console
$ head -1 /tmp/ex/web-01-20260819.csv
hostname,machine_id,os_id,os_version_id,architecture,scanned_at,name,version,type,language,purl,cpes,licenses,locations,found_by,sha256,change
```

| Column | Value |
|---|---|
| `hostname` | `web-01` |
| `machine_id` | |
| `os_id` | `debian` |
| `os_version_id` | `12` |
| `architecture` | `amd64` |
| `scanned_at` | `2026-08-19T11:49:06Z` |
| `name` | `flask` |
| `version` | `3.0.0` |
| `type` | `python` |
| `language` | `python` |
| `purl` | `pkg:pypi/flask@3.0.0` |
| `cpes` | `cpe:2.3:a:flask:flask:3.0.0:*:*:*:*:*:*:*` |
| `licenses` | `BSD-3-Clause` |
| `locations` | `…/flask-3.0.0.dist-info/METADATA;…/flask-3.0.0.dist-info/RECORD` |
| `found_by` | `python-installed-package-cataloger` |
| `sha256` | *(only with `--hash`)* |
| `change` | *(only with `--since`)* |

Multi-valued columns are joined with `;` **inside** the field, so a licence
containing a comma stays in its own column. `sha256` and `change` are always
present even when unused, so the column shape never varies with flags.

A real host produces the same shape at a very different scale — around 14,000
components on the machine this was developed on.

**[Full schema, NDJSON, CycloneDX and SQL loading →](docs/OUTPUT.md)**

Two runs on an unchanged machine produce **byte-identical output** apart from the
timestamps in `scan` — which is what makes these files worth diffing.

## Install

Every tagged release publishes static binaries and packages for `linux/amd64`
and `linux/arm64`, with a `SHA256SUMS` file to check them against.

Debian / Ubuntu:

```sh
sudo dpkg -i swinv_0.1.0-1_amd64.deb
```

RHEL / Fedora / SUSE:

```sh
sudo rpm -i swinv-0.1.0-1.x86_64.rpm
```

Or just drop the static binary on `PATH` — it has no dependencies at all:

```sh
install -m0755 swinv-v0.1.0-linux-amd64 /usr/bin/swinv
```

The packages install the binary to `/usr/bin/swinv`, the systemd units to
`/usr/lib/systemd/system/`, the man page to `swinv(8)`, and create
`/var/lib/swinv`. **The daily timer is shipped but deliberately not enabled** —
switching on a filesystem-wide scan without being asked would be rude:

```sh
sudo systemctl enable --now swinv.timer
```

Removing the package stops and disables the timer, but **leaves your collected
inventories in `/var/lib/swinv`** rather than deleting a fleet's history.

## What it finds

| Category | Examples |
|---|---|
| OS packages | dpkg/deb, rpm, apk, pacman, portage |
| Language packages | Python, npm/yarn, Go modules, Rust crates, Java/JVM, Ruby, PHP, .NET, … |
| Loose binaries | ELF binaries and statically-linked programs never installed by a package manager |

## Platform testing status

`swinv` is `v0.x`. Detection for every ecosystem below comes from Syft and is
wired in, but only the rows marked **Tested** have been exercised on real
hardware. Treat the rest as expected-to-work rather than verified, and please
report what you find.

On Fedora the rpm cataloger was verified against `rpm -qa`: 254 packages found
against 254 installed, with no package missed and none invented. That path
matters because Fedora keeps its database in SQLite, which is why `swinv` must
register a pure-Go SQLite driver — see [Building](#building).

| Surface | Status |
|---|---|
| Ubuntu / dpkg / amd64 | **Tested** on a real host, full scan and packaging |
| `.deb` install, systemd run, purge | **Tested** on a real Ubuntu host |
| Fedora / rpm / amd64 | **Tested** on a real host (Fedora 44 under WSL2) |
| `.rpm` install and run | **Tested** on Fedora via `dnf install` |
| apk / pacman / portage / nix cataloging | Wired via Syft; **not** run on a real host of that family |
| `linux/arm64` | Cross-compiled; **never executed** |

You are entitled to assume dpkg-on-amd64 works. You are not yet entitled to
assume the others do.

## Why not just use…?

| | What it gives you | Why `swinv` |
|---|---|---|
| **`syft` CLI** | The same detection engine — `swinv` imports it | Adds host identity, stable dated/rotating filenames, atomic writes, day-over-day deltas, and a flat CSV built for SQL. One binary, no JSON round-trip |
| **osquery** | Far broader host telemetry, SQL over live state | `swinv` is a oneshot binary, not an always-on agent with a daemon and its own query language. Nothing listens, nothing persists |
| **`dpkg -l` / `rpm -qa`** | Fast, already installed | OS packages only. Misses every language ecosystem and every unmanaged binary, and the output differs per distro |
| **A vulnerability scanner** | CVE matching | Different job. `swinv` emits CycloneDX and hands off — see [below](#vulnerability-scanning) |

## Output file naming

`--output-mode` controls how files accumulate across runs:

| Mode | Files produced | Behaviour |
|---|---|---|
| `dated` *(default)* | `web-01-20260819.json` | One file per day; re-running the same day replaces it |
| `overwrite` | `web-01.json` | **One fixed file, replaced every run** |
| `timestamped` | `web-01-20260819T140506.123Z.json` | **A new file for every run**, kept |

`--name` overrides the mode entirely and supports `{hostname}`, `{machine_id}`,
`{date}` and `{datetime}` (millisecond precision, so two runs in the same
second cannot collide).

Every write is atomic — temp file, `fsync`, `rename` — so a collector can never
pick up a half-written inventory, and killing `swinv` mid-write leaves the
previous file intact. `--latest-symlink` (on by default) keeps
`{hostname}-latest.{ext}` pointing at the newest file, which is what makes
`timestamped` mode practical to consume.

> `timestamped` mode has **no built-in retention**. Prune it yourself; see
> [troubleshooting](docs/TROUBLESHOOTING.md).

## Everyday flags

| Flag | Default | Meaning |
|---|---|---|
| `--root PATH` | `/` | Filesystem root to scan |
| `--out DIR` | `/var/lib/swinv` | Output directory |
| `--output-mode MODE` | `dated` | `dated`, `overwrite`, `timestamped` |
| `--format LIST` | `json,csv` | `json`, `csv`, `ndjson`, `cyclonedx-json` |
| `--stdout` | false | Write to stdout; requires exactly one `--format` |
| `--include-home` | false | Also scan `/home` and `/root` |
| `--offline` | false | Perform no network activity at all (skips the FQDN lookup) |
| `--perm OCTAL` | `0644` | Permission bits for the reports; the directory derives from it |
| `--skip-nested-rootfs` | false | Drop packages that came from a nested root filesystem (see Known limitations) |
| `--since PATH` | — | Diff against a previous report |
| `--hash` | false | Record a SHA-256 per component |
| `--max-memory SIZE` | — | Soft memory limit, e.g. `1536MiB` |
| `--timeout DURATION` | `30m` | Whole-run deadline |
| `--verbose` / `--quiet` | false | Per-stage timing / silence |

**[Full flag reference and exit codes →](docs/FLAGS.md)**

All human-readable output goes to **stderr**; only `--stdout` data goes to
stdout. Exit codes distinguish complete (`0`), partial (`1`), usage (`2`), fatal
(`3`) and timeout (`4`) — a single failing cataloger never aborts a run, because
an inventory missing one ecosystem beats no inventory.

## What is skipped by default

Exclusions are what make a scan take minutes instead of hours, so the defaults
are opinionated:

- Kernel and volatile trees: `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp`,
  `/var/cache`, `/var/log`, `/var/spool`, `/var/crash`.
- Container and orchestrator storage: `/var/lib/{docker,containers,containerd}`,
  `/var/lib/kubelet/pods`.
- Build and VCS noise: `**/.git/**`, `**/__pycache__/**`, `**/.cache/**`.
- **Every mount that is not a local filesystem** — NFS, CIFS, sshfs, autofs,
  overlay, squashfs — read from `/proc/self/mountinfo`. Walking a mounted NFS
  share is the single biggest cause of a scan taking hours. Disable with
  `--no-auto-exclude-mounts`.
- **`/home` and `/root`.** On the machine this was built on, `/home` alone was
  508,687 files across 86 `node_modules` trees — more than the rest of the
  filesystem combined. Home directories are also per-user, high-churn and
  privacy-sensitive, none of which is true of the machine's own software.
  `--include-home` turns them back on.

**Snap and Flatpak are scanned** — they are genuinely installed software. Snaps
are squashfs loop mounts, so `swinv` specifically carves `/snap` and
`/var/lib/snapd/snap` out of the "skip non-local filesystems" rule; a squashfs
image mounted anywhere else stays excluded. `--no-snap` / `--no-flatpak` opt out.

Whatever is skipped is always recorded in `scan.excluded`, with a note in
`scan.warnings`. Nothing is dropped silently.

## Change detection

`--hash` adds a SHA-256 of each component's primary file. Files backing *more
than one* component are deliberately not hashed — most debs cite
`/var/lib/dpkg/status`, and digesting it would give every package on the machine
the same hash and make all of them look changed whenever any one changed.

`--since previous.json` adds a `delta` block of added, removed and
version-changed components. Matching is on `(name, type)`, **not** version, so an
upgrade reads as one `changed` entry rather than a removal plus an unrelated
addition. `--delta-only` emits just the diff.

```sh
swinv --out /var/lib/swinv --output-mode timestamped \
      --since /var/lib/swinv/*-latest.json
```

**[Output formats, schema and SQL loading →](docs/OUTPUT.md)**

## Security and privacy

Worth knowing before you roll this out fleet-wide:

- **No inventory data is ever transmitted.** `swinv` opens no sockets to send
  results anywhere. The single exception to "no network at all" is a
  best-effort reverse-DNS lookup that fills `host.fqdn` — a normal name
  resolution against your configured resolver, bounded to two seconds and never
  fatal. It carries no scan data, but it does tell that resolver the host
  looked itself up. **`--offline` disables it**, making the run completely
  network-silent at the cost of one field. It is skipped automatically whenever
  `--root` is not `/`.
- **It records host identity**: hostname, `/etc/machine-id`, boot ID, kernel,
  DMI vendor/product, and non-loopback IPs and MAC addresses. That is what makes
  reports joinable across a fleet — but it means the files identify the machine.
  DMI serial and UUID are root-only and simply absent otherwise.
- **It records installed software paths.** With `--include-home`, that includes
  paths inside users' home directories. This is the main reason home directories
  are off by default.
- **Protect the output directory.** `--out` is created `0755` and files `0644`,
  so an inventory is world-readable by default. Tighten it if your threat model
  needs that.
- **The systemd unit is hardened but deliberately not sandboxed from the
  filesystem.** It sets `ProtectSystem=strict`, `ReadWritePaths=/var/lib/swinv`,
  `PrivateTmp`, `NoNewPrivileges`, and the `ProtectKernel*` / `ProtectClock` /
  `ProtectControlGroups` family. It pointedly does *not* set `ProtectHome`,
  `PrivateDevices`, `PrivateUsers` or `ProtectProc=invisible` — each would hide
  something the scan needs, and the unit documents why inline. Reading the whole
  tree is the tool's entire job.
- **No GPL/AGPL/LGPL anywhere in the dependency tree**, enforced by a CI gate
  that fails the build. See [licensing](#licensing).

## Performance

On a large developer workstation (~1M files, including a 156k-file source
checkout under `/opt`), a default full scan takes around 5 minutes and peaks near
2.3 GB RSS, producing ~14,000 components. A fleet server with a couple of
thousand packages and no source trees is a very different shape — measure your
own before drawing conclusions.

The one flag most worth setting is `--max-memory`. On that host
`--max-memory 1536MiB` used **30% less memory and ran 13% faster** than the
default, because a smaller heap means less to scan and better cache locality.

Two findings that will save you time, both measured:

- **`--catalogers os` does not make scanning cheap.** Syft indexes the whole
  filesystem when it builds its resolver, *before* cataloger selection applies.
  Narrowing catalogers narrows parsing, not the walk.
- **`--no-file-ownership` is faster but uses slightly *more* memory.** It is a
  speed lever, not a memory lever, despite looking like one.

**[Measured numbers, tuning guide and the full analysis →](docs/PERFORMANCE.md)**

## Known limitations

Read these before trusting the output.

### Nested root filesystems produce phantom packages

Scanning `/` walks into **any second root filesystem stored on the disk** — an
extracted tarball, a container rootfs backup, a chroot, a VM image, or a test
fixture — reads its package database, and reports those packages as installed.

Worse, they wear *this* host's distribution label, because distro detection
happens once per scan. On the machine `swinv` was developed on, the repository's
own 7-package test fixture appeared in the inventory as a Debian 12 `openssl`
on an Ubuntu 26.04 host, with nothing marking it as foreign.

`swinv` **warns** when it detects this, naming the directories it found:

```
found 1 nested root filesystem(s) containing their own package databases:
/opt/code/swinv/testdata/rootfs. Their packages are reported as installed and
carry this host's distribution label …
```

`--skip-nested-rootfs` drops them. It is off by default because scanning a
chroot or a mounted image is sometimes exactly what you want, and silently
discarding it would be its own surprise. The filter keys on *package-database
evidence*, so a genuinely installed package is never removed even when a nested
tree also references its files.

### Performance does not meet the original targets

A full scan takes minutes, not seconds, and peaks well above 512 MB. The cost is
Syft's whole-filesystem index, and `--catalogers os` does not avoid it. The
numbers are measured and published in [docs/PERFORMANCE.md](docs/PERFORMANCE.md)
rather than restated as goals.

### Only one platform has been exercised

See [Platform testing status](#platform-testing-status). dpkg on amd64 is
tested; the rpm, apk, pacman, portage and nix paths are wired in through Syft
and have never run on a real host of that family.

## Vulnerability scanning

`swinv` deliberately does not scan for vulnerabilities. Emit CycloneDX and hand
it to a scanner — for example Anchore's `grype`, which is a separate tool:

```sh
swinv --format cyclonedx-json --stdout > sbom.json
grype sbom:sbom.json
```

## Building

| Component | Pinned |
|---|---|
| Go | **1.26.6** |
| `github.com/anchore/syft` | **v1.51.0** |

```sh
make build          # bin/swinv, static
make test           # go test -race ./...
make lint           # go vet + golangci-lint
make license-check  # fail on any GPL/AGPL/LGPL/unknown dependency
make release        # linux/amd64 + linux/arm64 + SHA256SUMS
```

```console
$ ldd bin/swinv
	not a dynamic executable
```

`make packages` builds a `.deb` and an `.rpm` for the host architecture;
`make release` builds binaries and packages for both architectures plus
`SHA256SUMS`. Both need [nfpm](https://github.com/goreleaser/nfpm)
(`go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest`).

## Licensing

`swinv` is **Apache-2.0** and **community-owned**. See [`LICENSE`](LICENSE).

Copyright is held collectively by the contributors listed in
[`AUTHORS`](AUTHORS) — each retains copyright in their own work and licenses it
to everyone under Apache-2.0. There is no CLA and no copyright assignment. The
trade-off is deliberate and worth stating plainly: because no single party owns
the whole work, `swinv` **cannot be relicensed or dual-licensed** without the
agreement of every contributor. That is the protection community ownership
buys.

Syft is Apache-2.0, so importing it imposes no copyleft obligation; attribution
is in [`NOTICE`](NOTICE). **No GPL, AGPL or LGPL module may enter this binary** —
linking one in would force the whole combined work under the GPL. CI enforces
that with a hard gate (`make license-check`) that fails on any dependency whose
licence is copyleft or unidentified. Of 278 dependencies, none is copyleft.
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) is generated, not
hand-written.

## Architecture

```
cmd/swinv/          flags, wiring, exit codes — thin
internal/model/     output types + schema version. Stdlib only.
internal/hostfacts/ machine identity, read straight from kernel interfaces
internal/scan/      the Syft integration — the ONLY package that imports Syft
internal/output/    JSON, CSV, NDJSON, CycloneDX writers + atomic writes
```

`internal/scan` is the only package permitted to import Syft; everything
downstream operates on `internal/model` types. That keeps a Syft API break
contained to one package and leaves room for a second collection backend without
touching the writers.

## Documentation

| | |
|---|---|
| [Full CLI reference](docs/FLAGS.md) | Every flag, exit codes, recipes |
| [Output formats](docs/OUTPUT.md) | JSON schema, CSV columns, loading into SQL |
| [Performance](docs/PERFORMANCE.md) | Measured numbers and the tuning guide |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Symptom → cause → fix |
| [Contributing](CONTRIBUTING.md) | Build, test, architecture, the Syft landmines |
| [Security](SECURITY.md) | Reporting, and exactly what data a report contains |
| [Changelog](CHANGELOG.md) | What changed, and the versioning policy |
| [Specification](docs/INVENTORYCOLLECTORSPEC.md) | The spec of record, with rationale |

## Non-goals

No central server or phone-home. No configuration management, patching or
remediation. No vulnerability scanning. No Windows or macOS support. No TUI.
