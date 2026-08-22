# `swinv`

[![CI](https://github.com/chaugan/swinv/actions/workflows/ci.yml/badge.svg)](https://github.com/chaugan/swinv/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/chaugan/swinv)](https://github.com/chaugan/swinv/releases/latest)
[![Go](https://img.shields.io/github/go-mod/go-version/chaugan/swinv)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[![Linux](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-informational?logo=linux&logoColor=white)](#platform-testing-status)
[![Windows](https://img.shields.io/badge/Windows-amd64-informational?logo=windows&logoColor=white)](#windows)

**Local software inventory for Windows and Linux: one static binary, files on
disk, nothing leaves the host.**

`swinv` scans the machine it runs on and records every piece of installed
software it can find — OS packages on Linux, the registry on Windows, language
packages on both, and loose binaries that no package manager ever installed —
then writes the result to local JSON and CSV files.

On Linux it also records **what is actually listening and what is exposed at
the network edge** — including the software running inside Docker and
Kubernetes containers, identified from each container's own package database.
That is the question an inventory of packages cannot answer on its own.

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
  "schema_version": "1.7",
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
      "vendor": "Armin Ronacher",
      "purl": "pkg:pypi/flask@3.0.0",
      "cpes": ["cpe:2.3:a:flask:flask:3.0.0:*:*:*:*:*:*:*"],
      "licenses": ["BSD-3-Clause"],
      "locations": [
        "/usr/lib/python3/dist-packages/flask-3.0.0.dist-info/METADATA",
        "/usr/lib/python3/dist-packages/flask-3.0.0.dist-info/RECORD"
      ],
      "found_by": "python-installed-package-cataloger",
      "root": "/",
      "owned_by": "pkg:deb/ubuntu/python3-flask@3.0.0-1"
    }
  ]
}
```

`scan.warnings` and `scan.excluded` always record what was skipped and why, so a
consumer can tell a thin inventory from a complete one.

Three fields on that second component are worth calling out, because they exist
to stop a consumer drawing the wrong conclusion:

- **`vendor`** — who made it, taken from whatever the ecosystem records: an rpm
  `Vendor`, a dpkg `Maintainer`, a Python or npm `Author`, a Windows PE
  `CompanyName`.
- **`root`** — which filesystem root it was found in. `/` is the machine
  itself; anything else is a snap base, a container layer or a mounted image,
  which are separate operating systems with their own release and patch state.
- **`owned_by`** — the OS package that installed it, where one did. Ubuntu's
  `python3-flask` backports fixes without changing the upstream version, so
  assessing the PyPI row against upstream releases reports a patched host as
  badly out of date. An **empty** `owned_by` is equally meaningful: the package
  came from `pip` or `npm` and genuinely should be checked upstream.

The CSV is the same data, one row per component, with host identity repeated on
every row so files concatenate cleanly across a fleet. Rows are wide, so here is
one folded onto its 20 columns:

```console
$ head -1 /tmp/ex/web-01-20260819.csv
hostname,machine_id,os_id,os_version_id,architecture,scanned_at,name,version,type,language,purl,cpes,licenses,locations,found_by,sha256,change,vendor,root,owned_by
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

#### What is listening

Run as root on Linux, the report also carries a `services` block: every
listening socket, the process behind it, its systemd unit or container, and
which installed software owns its executable.

```console
$ sudo swinv --out /var/lib/swinv
swinv: services: 27 attributed to installed software, 3 running software nothing installed, 1 unidentified
swinv: wrote /var/lib/swinv/web-01-20260821T205516.499Z.json
swinv: wrote /var/lib/swinv/web-01-20260821T205516.499Z.csv
swinv: wrote /var/lib/swinv/web-01-20260821T205516.499Z-services.csv
```

```jsonc
{
  "endpoints": ["0.0.0.0:22/tcp", "[::]:22/tcp6"],
  "pid": 811,
  "executable": "/usr/sbin/sshd",
  "unit": "ssh.service",
  "components": ["pkg:deb/ubuntu/openssh-server@1:10.2p1-2ubuntu3.5"],
  "confidence": "high",
  "evidence": ["socket 0.0.0.0:22/tcp held by pid 811", "…"]
}
```

**The middle number in that summary is the one to read.** Three of the
thirty-one services on that host are software that is serving traffic and that
no package manager installed — a vendor binary under `/opt`, and two copies of
`/usr/local/bin/node`. Nothing in a package list says so.

`confidence` is recorded rather than implied, and every finding carries the
`evidence` it rests on, because a bare claim that "port 443 is nginx 1.24" is
indistinguishable from a guess by the time it reaches anyone. Socket-activated
ports are marked as such rather than blamed on `systemd`, since the daemon may
not be running at all. Unprivileged, the ports are still reported and the
processes behind them mostly are not — which is stated, not hidden.

It all comes from `/proc`: no `ss`, no `netstat`, no `lsof`, no D-Bus.
`--no-services` skips it; `--no-service-command` keeps it but drops the command
lines, which is where secrets end up.

#### What is exposed, and what is inside the containers

The same run records the network edge: one row per listening socket in the
**host** network namespace, with the software behind it — following a published
port into the container that answers it.

```jsonc
{
  "address": "0.0.0.0", "port": 80, "protocol": "tcp",
  "bind_scope": "wildcard",
  "executable": "/usr/bin/docker-proxy",
  "backend": {"container": "9d5a98d0dc04", "executable": "/usr/sbin/nginx"},
  "image": {"ref": "nginxinc/nginx-unprivileged:1.27-alpine", "manifest_digest": "sha256:…"},
  "components": ["pkg:apk/alpine/nginx@1.27.5-r1?arch=x86_64&distro=alpine-3.21.3"],
  "confidence": "high"
}
```

That PURL is the point. It comes from the **container's own package database**,
read through `/proc/<pid>/root` — an Alpine container on an Ubuntu host — and
it is a coordinate Grype and Trivy match today. An image reference is not:
there is no `oci` matcher anywhere in the chain, so an image PURL alone yields
a component that gets reported clean because nothing ever looked at it. swinv
emits the image digest as a *locator*, on its own field, never as an identity.

`containers[]` lists every container and what it runs, published or not, with
its own OS: `rhel-8.10`, `alpine-3.21.3`, `wolfi-20230201` — each a different
operating system from the host, deciding which advisories apply.

**`bind_scope` is about the bind, not about reachability.** swinv reads no
firewall, no NAT table and no security group, so there is no "public" and
nothing says "internet-facing". And because a port published by a netfilter
rule has no listening socket at all — Kubernetes NodePort, Docker with
`userland-proxy` disabled, Podman's default netavark — every report carries
`scan.exposure_blind_spots` naming what it could not see. **A short exposure
list means nothing until you have read that array.**

**[Why this exists and how it is built →](docs/SERVER-ROLES.md)**

**[Full schema, NDJSON, CycloneDX and SQL loading →](docs/OUTPUT.md)**

Two runs on an unchanged machine produce **byte-identical output** apart from the
timestamps in `scan` — which is what makes these files worth diffing.

## Install

Every tagged release publishes static binaries and `.deb`/`.rpm` packages for
`linux/amd64` and `linux/arm64`, with a `SHA256SUMS` file to check them against.
Pick whichever fits how you manage machines.

### Debian, Ubuntu and derivatives

```sh
VER=$(curl -sI https://github.com/chaugan/swinv/releases/latest | sed -n 's|.*/tag/v\([0-9.]*\).*|\1|p' | tr -d '\r')
curl -LO "https://github.com/chaugan/swinv/releases/download/v$VER/swinv_${VER}-1_amd64.deb"
sudo dpkg -i "swinv_${VER}-1_amd64.deb"
```

Package filenames must carry their version, so this resolves the current one
first. Or just take the `.deb` from the
[releases page](https://github.com/chaugan/swinv/releases/latest).

### RHEL, Fedora, SUSE and derivatives

```sh
VER=$(curl -sI https://github.com/chaugan/swinv/releases/latest | sed -n 's|.*/tag/v\([0-9.]*\).*|\1|p' | tr -d '\r')
curl -LO "https://github.com/chaugan/swinv/releases/download/v$VER/swinv-${VER}-1.x86_64.rpm"
sudo dnf install --nogpgcheck "./swinv-${VER}-1.x86_64.rpm"   # upgrade with: dnf upgrade
```

The `./` prefix is required, or `dnf` searches the repositories for a package by
that name. `--nogpgcheck` is needed because releases are not yet signed.

### Any Linux — the static binary

It has no dependencies of any kind, not even libc, so this works everywhere
including Alpine and distroless images:

```sh
curl -LO https://github.com/chaugan/swinv/releases/latest/download/swinv-linux-amd64
curl -LO https://github.com/chaugan/swinv/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
sudo install -m0755 swinv-linux-amd64 /usr/bin/swinv
```

Use `swinv-linux-arm64` for 64-bit ARM. Every release publishes each binary
twice — once with the version in the name for archival, and once without, so
these `latest/download` URLs keep working and never need editing. **Always check the digest** — you are about
to run this as root against your whole filesystem.

### With Go

```sh
go install github.com/chaugan/swinv/cmd/swinv@latest
```

`go install` applies no `-ldflags`, so `swinv --version` falls back to the module
version recorded in the build info. It reports the module version rather than a
git description, which is correct but differs from a release binary.

### Ansible, for a fleet

```yaml
- name: Install swinv
  ansible.builtin.get_url:
    url: "https://github.com/chaugan/swinv/releases/latest/download/swinv-linux-{{ 'arm64' if ansible_architecture == 'aarch64' else 'amd64' }}"
    dest: /usr/bin/swinv
    mode: "0755"
    checksum: sha256:https://github.com/chaugan/swinv/releases/latest/download/SHA256SUMS

- name: Install the systemd units
  ansible.builtin.get_url:
    url: "https://raw.githubusercontent.com/chaugan/swinv/main/packaging/swinv.{{ item }}"
    dest: "/usr/lib/systemd/system/swinv.{{ item }}"
    mode: "0644"
  loop: [service, timer]
  notify: reload systemd

- name: Enable the daily timer
  ansible.builtin.systemd:
    name: swinv.timer
    enabled: true
    state: started
    daemon_reload: true
```

`get_url` verifies the digest against the published `SHA256SUMS`, so the
download is checked rather than trusted.

### In a container image

A static binary needs no base image at all:

```dockerfile
FROM scratch
COPY swinv-linux-amd64 /swinv
ENTRYPOINT ["/swinv"]
```

To inventory the *host* from a container, mount its root read-only and scan
that path rather than `/`:

```sh
docker run --rm -v /:/host:ro -v "$PWD":/out \
  swinv:latest --root /host --out /out --offline
```

`swinv` recognises a mounted tree as a root filesystem when it contains
`etc/os-release`, and applies the usual layout exclusions to it — otherwise
this would walk `/host/proc`, `/host/sys` and every home directory on the
machine. It says so in `scan.warnings` rather than doing it silently. Verified:
scanning an Ubuntu host this way found 1,587 deb components against `dpkg`'s
1,586 installed, correctly leaving out the 11 packages that were removed with
their config files kept.

### From source

```sh
git clone https://github.com/chaugan/swinv && cd swinv
make build            # -> bin/swinv
```

Needs Go 1.26.6 or newer; see [Building](#building).

### After installing

The packages place the binary at `/usr/bin/swinv`, the systemd units in
`/usr/lib/systemd/system/`, the man page at `swinv(8)`, and create
`/var/lib/swinv`. **The daily timer ships deliberately disabled** — turning on a
filesystem-wide scan uninvited would be rude:

```sh
sudo systemctl enable --now swinv.timer
```

Removing the package stops and disables the timer but **leaves your collected
inventories in `/var/lib/swinv`** rather than deleting a fleet's history.

> Not yet available: Homebrew, AUR, Nix and hosted apt/dnf repositories. Those
> need infrastructure this project does not have yet, and are not claimed here
> until they exist.

## Platform testing status

`swinv` is `v0.x`, but the OS package catalogers are no longer taken on trust.
Each was run against a real package database and its count compared with that
distribution's own package manager:

| Distribution | Package manager | Result |
|---|---|---|
| Alpine | apk | **16 / 16** — and the static binary runs on musl |
| Debian | dpkg | **78 / 78** |
| Ubuntu | dpkg | full scan on a real host, 14,190 components |
| Fedora | rpm | **147 / 147** in a container, **257 / 257** on a real host |
| Arch | pacman (`alpm`) | **137 / 137** |
| openSUSE Tumbleweed | rpm | **123 / 123** |
| Gentoo | portage | **296 / 296** |

Exact agreement on every one, with `os_id` correctly detected in each case.
Alpine matters beyond its own row: `swinv` is built `CGO_ENABLED=0`, and that
run is what proves the binary carries no glibc assumption.

Beyond OS packages, on real hosts:

| Surface | Status |
|---|---|
| `.deb` install, systemd run, purge | **Tested** on Ubuntu |
| `.rpm` install and upgrade | **Tested** on Fedora via `dnf` |
| Go modules and ELF binaries | **Tested** on Fedora, CVE-matched via `grype` |
| CycloneDX → `grype` | **Tested** — 234 matches from a 568-component document |
| `linux/arm64` | **Tested** under emulation — apk 16/16, dpkg 78/78, rpm 147/147, `architecture` correctly `arm64` |

All of this runs in CI on every push, so a Syft upgrade that quietly stops
reading one package database shows up as a count mismatch rather than as a
thinner inventory noticed months later.

The remaining caveat is honest rather than alarming: arm64 is verified under
QEMU emulation, not on physical ARM hardware. Emulation exercises the code but
not the machine, so if you run this on a Raspberry Pi or an ARM instance, that
is still worth reporting.

### Windows

| Surface | Status |
|---|---|
| uninstall registry | **Tested** on Windows 11 25H2 and Server 2025 — 380 and 423 products |
| Store and MSIX packages | **Tested** — 135 packages on a real laptop |
| Windows servicing state | **Tested** — cumulative update version asserted equal to the host's build and UBR |
| MFT enumeration | **Tested** — 2,889,563 records in 12 s, every path resolved |
| PE version extraction | **Tested** — 14,769 components from 19,550 files |
| Python and npm manifests | **Tested** — 2,266 packages from 2,598 manifests |
| Host identity | **Tested** — `os_id`, `machine_id`, build and UBR, on client and server |

Every one of those runs on a `windows-latest` runner on each push, including an
end-to-end collection with and without `--full-scan`. The runner is a server
edition, which is how the client/server build-number collision was found; the
client numbers above come from a real laptop.

## Windows

Windows keeps its record of installed software in the registry, not on the
filesystem, so `swinv` reads it there. A default run touches no files at all and
finishes in milliseconds:

```console
> swinv --out C:\inventory --format json
swinv: scanning the uninstall registry ...
swinv: registry: 380 installed products, 187 distinct install locations
swinv: appx: 135 Store and MSIX packages
swinv: updates: 4 installed servicing packages
swinv: found 519 components in 27ms
```

That is the whole default scan: no elevation, no file opened, three registry
sources.

| Source | Gives |
|---|---|
| uninstall registry | installed applications, with version and publisher |
| package repository | Store and MSIX apps |
| component store | Windows servicing state — cumulative update, servicing stack, .NET rollup |

### `--full-scan`

Adds everything the registry does not record — software unpacked into a
directory, vendor tools, anything copied onto the machine — plus Python and npm
packages. It needs an elevated process and an NTFS volume.

It does **not** walk directories. It enumerates the Master File Table: 2.9
million records in five seconds on a real laptop, opening nothing. Then it
discards what the registry already accounts for and what belongs to Windows
itself, and opens only the remainder — **19,549 files of 99,920** on that
machine, an 80% reduction in the one operation that costs anything.

| | |
|---|---|
| MFT enumeration | 2,889,563 records in 12 s, no file opened |
| attributed to a registry product | 26,827 — version already known, not opened |
| operating-system and Store territory | 53,553 — accounted for elsewhere |
| **opened to extract a version** | **19,550** |

The first `--full-scan` on a machine is slow and the rest are not. Antivirus
scans each executable the first time it is opened and caches the result, so the
same command took **14 minutes** cold and **1 second** warm — a scheduled task
pays that once.

`--volumes D:` or `--volumes D:,E:` selects which volumes to enumerate, and
**replaces** the default of `C:` rather than adding to it.

### Language ecosystems

Python and npm packages are found during the same MFT pass, by their manifests —
`*.dist-info/METADATA`, `*.egg-info/PKG-INFO`, `package.json` — and only those
files are opened. They carry real PURLs, since `pypi` and `npm` are canonical
PURL types.

The Linux collector reads roughly 40 ecosystems through Syft. Windows reads
these two: Syft's resolver opens every file it indexes, which is the strategy
this design exists to avoid. Cargo, Maven, RubyGems, NuGet and the rest are not
covered.

### Host identity

`os_id`, `os_version_id`, `os_pretty_name`, `machine_id` and `kernel_release`
come from the registry, so a Windows report groups and joins alongside a Linux
one. `machine_id` is derived from `MachineGuid` and normalised to the same
32-hex-character shape as a Linux `machine-id`.

Two Windows quirks are handled: the registry still reads `Windows 10 Pro` on
Windows 11 hosts, and client and server share build numbers — Windows 11 24H2
and Server 2025 are both `26100` — so a server reports its release year rather
than a client major.

### What is out of scope

Operating-system components are **not** inventoried file by file. `C:\Windows\
WinSxS` held 39,536 executables on a real machine — 40% of every candidate on
the volume — and they are hard-linked servicing copies that say little
individually. The installed servicing packages express the same thing in the
form an operator patches by, with the cumulative update's version equal to the
host's build and UBR.

Store apps and per-user applications are registered per user, so a scan running
as a service account sees that account's and no other's.

**[Design, measurements and open questions →](docs/WINDOWS.md)**

## Why not just use…?

| | What it gives you | Why `swinv` |
|---|---|---|
| **`syft` CLI** | The same detection engine — `swinv` imports it | Adds host identity, stable dated/rotating filenames, atomic writes, day-over-day deltas, and a flat CSV built for SQL. One binary, no JSON round-trip |
| **osquery** | Far broader host telemetry, SQL over live state | `swinv` is a oneshot binary, not an always-on agent with a daemon and its own query language. Nothing listens, nothing persists |
| **`dpkg -l` / `rpm -qa`** | Fast, already installed | OS packages only. Misses every language ecosystem and every unmanaged binary, and the output differs per distro |
| **`grype dir:/`** | Package discovery *and* CVE matching in one pass — also Anchore's, also Syft-powered | A complement, not a competitor. `grype` needs a vulnerability database it downloads and refreshes; `swinv` runs `--offline` with no network at all. `grype` produces findings, `swinv` produces an inventory: host identity, dated files, deltas, CSV. Keep the SBOM and you can re-match new CVEs daily **without re-walking the filesystem** — see [below](#vulnerability-scanning) |

## Output file naming

`--output-mode` controls how files accumulate across runs:

| Mode | Files produced | Behaviour |
|---|---|---|
| `dated` | `web-01-20260819.json` | One file per day; re-running the same day replaces it |
| `overwrite` | `web-01.json` | **One fixed file, replaced every run** |
| `timestamped` *(default)* | `web-01-20260819T140506.123Z.json` | **A new file for every run**, kept |

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
| `--output-mode MODE` | `timestamped` | `timestamped`, `dated`, `overwrite` |
| `--format LIST` | `json,csv` | `json`, `csv`, `ndjson`, `cyclonedx-json` |
| `--stdout` | false | Write to stdout; requires exactly one `--format` |
| `--include-home` | false | Also scan `/home` and `/root` |
| `--offline` | false | Perform no network activity at all (skips the FQDN lookup) |
| `--perm OCTAL` | `0644` | Permission bits for the reports; the directory derives from it |
| `--skip-nested-rootfs` | false | Drop packages that came from a nested root filesystem (see Known limitations) |
| `--no-services` | false | Linux: do not report what is listening |
| `--no-containers` | false | Linux: do not look inside containers for what they run |
| `--no-service-command` | false | Linux: keep the services block, drop the command lines |
| `--since PATH` | — | Diff against a previous report |
| `--hash` | false | Record a SHA-256 per component |
| `--fast` | false | Scan at normal priority and full parallelism (see below) |
| `--max-memory SIZE` | — | Soft memory limit, e.g. `1536MiB` |
| `--debug-stacks-after DUR` | — | Dump goroutine stacks if the scan is still running, for a run that appears hung |
| `--timeout DURATION` | `30m` | Whole-run deadline |
| `--verbose` / `--quiet` | false | Per-stage timing / silence |
| `--full-scan` | false | Windows: also enumerate the filesystem and read manifests |
| `--volumes LIST` | `C:` | Windows: volumes to enumerate, e.g. `D:` or `D:,E:` — replaces the default |

**[Full flag reference and exit codes →](docs/FLAGS.md)**

### swinv gets out of the way by default

An inventory collector is background maintenance: it runs unattended, on a
timer, on machines doing real work, and nobody is waiting for its answer. So by
default swinv runs at `nice 10` with idle I/O priority on Linux, in background
priority mode on Windows, and with a quarter of the CPUs as cataloger workers.
Worker count matters here beyond speed — it sets how deep an I/O queue the scan
presents to the kernel, and that is most of what decides whether the rest of the
machine feels slow while it runs.

It costs about a third of the runtime: `/usr` on an 8-core host took 41.6 s by
default and 30.6 s with `--fast`. Pass `--fast` when a person is waiting.

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
- **It records service command lines.** The `services` block includes each
  listening process's `argv`, and command lines are where secrets end up — a
  `--password` on a daemon's ExecStart, a connection string with credentials in
  it. Anything visible in `ps` can therefore reach an inventory file that gets
  copied elsewhere. **`--no-service-command`** drops that one field;
  **`--no-services`** drops the section.
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

Each such component records the root it came from in `root`, and has the
distribution claim stripped from its PURL — a Debian 12 `openssl` inside a snap
base is reported as `pkg:deb/openssl@3.0.11-1~deb12u2` rather than as an Ubuntu
package, because asserting the scanning host's distribution over it would make
both "is it affected" and "is it fixed" meaningless. Where the nested root
states its own release, `attributes.root_os_id` and `root_os_version_id` carry
it.

What remains is that those packages are still *reported*, which is usually
right — a base snap is real software on the machine — but means a count of
"installed packages" includes them.

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

### arm64 is verified under emulation, not on real hardware

See [Platform testing status](#platform-testing-status). The arm64 binary is
exercised in CI through QEMU, which runs the code but is not the same as a
physical ARM machine.

## Vulnerability scanning

`swinv` deliberately does not scan for vulnerabilities. Emit CycloneDX and hand
it to a scanner — for example Anchore's [`grype`](https://github.com/anchore/grype),
whose Syft library `swinv` is built on:

```sh
swinv --format cyclonedx-json --stdout --offline > sbom.json
grype sbom:sbom.json
```

**Why separate them at all**, when `grype dir:/` would do both?

- **The expensive half is the filesystem walk.** Matching an SBOM against a CVE
  database takes seconds; walking a million files takes minutes. Store the
  SBOM and you can re-match every morning as new advisories land, without
  touching the host again.
- **CVE results go stale when the host has not changed.** An inventory is a
  fact about a machine at a point in time and stays true; a vulnerability
  report is a join against a database that moves daily. Keeping them separate
  means you can tell "the machine changed" from "the advisories changed" —
  which is exactly what `--since` answers.
- **`grype` needs the network to fetch and refresh its database.** `swinv
  --offline` performs no network activity whatsoever, which matters on
  air-gapped or egress-restricted fleets. Collect the SBOMs and match them
  somewhere with connectivity.

Verified end to end on Fedora 44: a 568-component CycloneDX document was
accepted by `grype` v0.117.0, which resolved both `rpm` and `go-module`
components and returned **234 vulnerability matches**. That is a stronger
result than "it parsed" — CVE matching is a join on package identity, so it
also confirms the PURLs are well-formed and correct.

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
| [Windows](docs/WINDOWS.md) | Design, measurements, and what Windows support does not yet cover |
| [Server roles](docs/SERVER-ROLES.md) | Detecting what is running and serving, and the product behind it |

## Non-goals

No central server or phone-home. No configuration management, patching or
remediation. No vulnerability scanning. No Windows or macOS support. No TUI.
