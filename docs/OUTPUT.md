# swinv output formats

The complete reference for every file `swinv` writes: the schema, the four
formats, the field-by-field data model, the identity and ordering guarantees
consumers may rely on, and how to load the result into a database.

Part of the [swinv](../README.md) documentation.

---

## Schema version and the compatibility promise

Every JSON document carries a `schema_version` at the top. The current value is
**`1.11`**, defined as `model.SchemaVersion` in `internal/model/model.go`.

```json
"schema_version": "1.11"
```

**1.10 → 1.11** added shared-library linkage:

| Addition | Appears in |
|---|---|
| `services[].links`, `containers[].services[].links` | JSON, services CSV column 21, CycloneDX dependency edges |
| `Report.links` | JSON, with `--elf-scope all` |
| a `record_type: "link"` record | NDJSON, with `--ndjson-include links` |

Every ELF binary already carries a database of its own dependencies: the
`DT_NEEDED` entries name the shared libraries it loads, and the dynamic symbol
table names every function it imports, with versions. swinv reads both without
executing anything and joins each library to the package that owns it - so a
CVE in a common library can be ranked by which network-facing services
actually load it, instead of flagging every machine that merely has it on
disk.

```jsonc
"links": [
  {"soname": "libcrypto.so.3",
   "path": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
   "purl": "pkg:deb/ubuntu/libssl3t64@3.5.5-1ubuntu3.3?upstream=openssl",
   "n_symbols": 120},
  {"soname": "libz.so.1", "path": "/usr/lib/x86_64-linux-gnu/libz.so.1.3.1",
   "purl": "pkg:deb/ubuntu/zlib1g@1.3.1", "transitive": true}
]
```

Resolution follows `ld.so` without running it: `RPATH`/`RUNPATH` with
`$ORIGIN`, `/etc/ld.so.conf`, then the standard directories - and symlinks are
chased to the real file inside the probed filesystem, because the soname path
is usually an ldconfig-made link no package ships, and for a container the
chase must not escape to the host. A container's links resolve against that
container's own libraries: nginx in an Alpine container links
`pkg:apk/alpine/libcrypto3@3.3.3-r0`, not the host's openssl.

**Three limits, stated in the data rather than discovered.** `DT_NEEDED` is
link-time truth only - nginx modules, Python extensions, PAM and NSS arrive by
`dlopen` and are invisible, and the service evidence says so. A symbol list
names the API entry points the binary calls, not the code that runs; most CVEs
live in internal functions that appear in no import table, so "loads the
library" is the reliable signal and `--elf-symbols` output is supporting
evidence, never a verdict. And a link with a `path` but no `purl` is a library
nothing installed owns - for a CVE consumer the more interesting case, not the
less.

`--elf-scope` picks the population: `listening` (default - the executables
behind open ports, milliseconds), `all` (every ELF under the standard binary
directories: 5,845 binaries and ~36,000 link records on the development host,
about a minute of walk), or `off`. With `--heartbeat`, link records are
suppressed on an unchanged scan - they derive from the installed software,
which is exactly what the digest tracks - while exposure and container records
still flow.

**1.9 → 1.10** added the self-describing scan manifest:

| Addition | Appears in |
|---|---|
| `scan.scan_id` | JSON |
| `scan.sources` | JSON |
| `schema_version`, `scan_id`, `swinv_version`, `counts`, `sources`, `duration_ms` on the heartbeat record | NDJSON |

Both are additive and omitted when never computed. See
[the manifest](#the-manifest) below.

**1.8 → 1.9** added the inventory heartbeat:

| Addition | Appears in |
|---|---|
| `scan.inventory_digest`, `scan.inventory_unchanged` | JSON |
| a `record_type: "heartbeat"` record | NDJSON, with `--heartbeat` |

See [the heartbeat](#the-heartbeat) below. Nothing changes without
`--heartbeat`: the fields are omitted and the NDJSON stream is exactly what it
was.

**1.7 → 1.8** brought the network edge to Windows:

| Addition | Appears in |
|---|---|
| `Service.os_component`, `Exposure.os_component` | JSON, services CSV column 20, exposure CSV column 18 |

`services[]`, `exposure[]` and `containers[]` now exist on Windows too - from
`iphlpapi` for the sockets and from the local Docker engine for the containers,
since a Docker Desktop container is a Linux process inside a virtual machine
that no Windows API reaches.

`os_component` came with them, and it is the field to know about: on Windows
most of what listens is the operating system, and `medium` would otherwise
describe `svchost.exe` as software running outside package management. **Filter
it out before treating `medium` as "unmanaged software"**, or every Windows
host contributes several dozen false entries. It is never set on Linux, where
the OS's own binaries are package-owned like any other.

**1.6 → 1.7** added the network edge:

| Addition | Appears in |
|---|---|
| `Report.exposure` | JSON, and a separate `-exposure.csv` file |
| `Report.containers` | JSON, and CycloneDX `services[]` with `trustZone` |
| `scan.firewall_examined`, `scan.exposure_blind_spots` | JSON, and repeated on every exposure CSV row |
| `Service.processes`, `Service.published_as` | JSON, services CSV columns 18-19 |
| Container packages in `components[]` with `root: "container:<id>"` | JSON, CSV, NDJSON, CycloneDX |

See [`exposure`](#exposure) and [`containers`](#containers) below.

**`services[].endpoints` did not change.** It is still an array of strings in
the same order. Retyping it to objects would have been a silent break for the
normal fate of a fleet inventory - an Elasticsearch mapping conflict rejects
documents at ingest, with nothing to connect the failure to swinv - so the
structured form lives in the new `exposure` array instead.

**`services[]` did not change meaning either.** It is still the host network
namespace and nothing else. Container listeners went into `containers[]`
rather than being added here, because every consumer that wrote
`select(.endpoints[] | startswith("0.0.0.0"))` reads that array as "reachable
on this machine", and quietly adding container-internal ports would have made
that query wrong without changing a single field name.

**1.5 → 1.6** added one thing:

| Addition | Appears in |
|---|---|
| `Report.services` | JSON, CycloneDX `services[]` + `dependencies[]`, and a separate `-services.csv` file |

What is listening on the machine, and which of the installed software is behind
it. See [`services`](#services) below, and
[docs/SERVER-ROLES.md](SERVER-ROLES.md) for why it exists.

It is a **top-level array, not a component field**: a component appears once,
a service appears once per listening process, and most components are behind no
service at all. The component rows and the CSV column order are untouched, so
every 1.5 consumer keeps working unchanged.

`services` is absent - not empty - when services were never collected: on
Windows, with `--no-services`, or when `--root` points at a tree other than
this machine. An empty array means the scan looked and found nothing listening.

**1.4 → 1.5** added one thing:

| Addition | Appears in |
|---|---|
| `Component.owned_by` | JSON, NDJSON, CSV column 20 |

The PURL of the OS package that owns a component's files, where one does.

A distribution-installed language package is reported twice, and both rows are
right: the OS package is what the vendor patches, the ecosystem package is what
upstream advisories are written against. Neither should be dropped. But without
a link, a consumer assessing the ecosystem row against upstream compares a
backported version against upstream's own numbering - Ubuntu's
`python3-cryptography 2.1.4-1ubuntu1.4+esm1` is patched, while PyPI's
`cryptography 2.1.4` reads as thirty-seven releases behind. One reported host
produced 442 false findings that way.

```json
{ "name": "cryptography", "version": "2.1.4", "type": "python",
  "owned_by": "pkg:deb/ubuntu/python3-cryptography@2.1.4-1ubuntu1.4%2Besm1" }
```

**An empty `owned_by` is meaningful**: nothing owns the files, so the component
was installed by `pip`, `npm` or a virtualenv rather than by the distribution,
and *should* be assessed against upstream. It is also empty when
`--no-file-ownership` was passed, since that flag disables the computation this
comes from.

Only an OS package can be an owner, and only an ecosystem package can be owned.
One `deb` owning another's files is ordinary and says nothing about backporting,
since one vendor patches both. Ownership never crosses a filesystem `root`.

**1.3 → 1.4** changed one thing:

| Change | Effect |
|---|---|
| `Component.version` is now omitted when unknown | It was emitted as the literal `"UNKNOWN"` |
| `Component.root` added | Which filesystem root a component was found in |
| `root` participates in deduplication | Same-named packages in different roots stay separate |

Syft writes `"UNKNOWN"` when a cataloger cannot determine a version. That is
worse than an absent field rather than merely untidy: it is valid syntax in
several version grammars, and under Debian ordering it has no epoch, so it
sorts below every real release. A consumer asking *"is the installed version
below the fixed version"* gets **yes** - for every advisory ever filed against
that package. A downstream matcher reported exactly that against `git` in a
snap base.

**`root`** is `/` for software installed on the scanned machine, or the path of
a nested root - a snap base, a container layer, an unpacked image. It is part
of a component's identity, so two packages of the same name and version in
different roots are two rows rather than one merged row whose `locations` span
both.

A nested root that states its own release carries it in
`attributes.root_os_id` and `attributes.root_os_version_id`. A base snap is a
different operating system - `core18` is Ubuntu 18.04 while the host may be
26.04 - and consumers were otherwise inferring that from the directory name,
which is a naming convention rather than a fact.

Packages found under a nested root have the distribution stripped from their
PURL: `pkg:deb/ubuntu/openssl@3.0.11-1~deb12u2?distro=ubuntu-26.04` becomes
`pkg:deb/openssl@3.0.11-1~deb12u2`. Syft stamps every package with the *scanned
host's* distribution, and for a Debian package inside a snap base that is not
merely unhelpful - a consumer matching `distro=` compares a Debian version
against Ubuntu's fixed versions and gets a meaningless answer in both
directions. A missing qualifier is honest where a wrong one is not.

**Consumers must treat `version` as optional and must not compare it when
absent.** On one Ubuntu host 6,480 of 10,850 components have no determinable
version, almost all of them kernel modules.

**1.2 → 1.3** added exactly one thing:

| Addition | Produced by | Appears in |
|---|---|---|
| `Component.attributes` | the Windows catalogers | JSON, CycloneDX properties |

A string map for ecosystem-specific identity that does not deserve a column of
its own: a Windows product code, the originating registry key, an install
scope, the several version strings a PE resource carries. A map rather than more
fields, because the alternative is a `Component` that grows a field per platform
and is mostly empty on every one of them.

**Deliberately not in the CSV.** The fixed column shape is what lets CSV files
be concatenated across machines, and a map has no fixed shape. JSON and
CycloneDX carry it; CSV consumers lose nothing they had.

**1.1 → 1.2** added exactly one thing:

| Addition | Produced by | Appears in |
|---|---|---|
| `Component.vendor` | always, where the ecosystem records it | JSON, CSV column 18, CycloneDX `publisher` |

`vendor` is the organisation behind a component, taken from whichever field its
ecosystem uses: an rpm `Vendor`, a dpkg or apk `Maintainer`, a Python or npm
`Author`, `Vendor` from a systemd ELF package note, or `CompanyName` from a
Windows PE version resource. Those are related but not identical facts, so the
raw value is kept rather than normalised into a single invented definition.

It is frequently empty - measured at 23% of components on a full Debian-family
host, ranging from 66% for `deb` down to 0% for kernel modules, which have no
such concept. Treat its absence as "not recorded", never as "no vendor".

**1.0 → 1.1** added exactly two things:

| Addition | Produced by | Appears in |
|---|---|---|
| `Component.sha256` | `--hash` | JSON, CSV column 16 |
| `Report.delta` | `--since` | JSON |

Both are **additive**, and both are omitted from the JSON when the flag that
produces them was not used. **A consumer written against 1.0 still parses a 1.1
document**: no field was renamed, removed, retyped, or reordered.

The promise, plainly:

- The **minor** version is bumped for additive changes - new optional fields,
  new columns appended to the end of the CSV. Existing fields keep their name,
  their type, and their meaning.
- The **major** version is bumped for anything that breaks that. Nothing has
  yet.
- The CSV's two 1.1 columns (`sha256`, `change`) were appended at the **end**,
  so a 1.0 row is a prefix of a 1.1 row.

Read `schema_version` if you care; ignore it safely if you only read fields you
already know.

---

## The four formats

`--format` takes a comma-separated list; the default is `json,csv`. Each format
has a fixed extension, and the output filename is the `--name` basename plus
that extension.

| `--format` | Extension | Example filename | Reach for it when |
|---|---|---|---|
| `json` | `.json` | `web-01-20240309.json` | You want the whole report - host facts, scan metadata, warnings, delta. The only format that is a valid `--since` baseline. |
| `csv` | `.csv` | `web-01-20240309.csv` | You are loading a fleet into a spreadsheet or a SQL database. Flat, one row per component, host identity on every row. |
| `ndjson` | `.ndjson` | `web-01-20240309.ndjson` | You are streaming into a log pipeline (Vector, Filebeat, Loki, `jq`). One self-describing object per line. |
| `cyclonedx-json` | `.cdx.json` | `web-01-20240309.cdx.json` | You are handing the inventory to a vulnerability scanner or any other SBOM consumer. |

With `--latest-symlink` (on by default) each format also gets a
`{hostname}-latest.{ext}` symlink - `web-01-latest.cdx.json`, and so on.

`--stdout` writes to standard output instead of files and requires exactly one
`--format`. All human-readable logging goes to stderr, so a pipe is always
clean:

```sh
swinv --format json --stdout | jq '.components | length'
```

Every file write is atomic (staged next to the target, `fsync`, `rename`), so a
collector can never pick up a half-written inventory.

---

## JSON

A single indented document (two spaces), UTF-8, terminated by a newline. HTML
escaping is disabled, so PURLs and CPEs are written literally rather than with
`<`-style escapes.

```jsonc
{
  "schema_version": "1.3",

  "tool": {                                  // what produced this file
    "name": "swinv",
    "version": "0.1.0",
    "commit": "a1b2c3d",
    "syft_version": "v1.51.0"
  },

  "host": {                                  // which machine it describes
    "hostname": "web-01",
    "fqdn": "web-01.example.net",
    "machine_id": "0123456789abcdef0123456789abcdef",
    "boot_id": "1f0c2f9c8b7a4d5e9f0a1b2c3d4e5f60",
    "os_id": "ubuntu",
    "os_version_id": "24.04",
    "os_pretty_name": "Ubuntu 24.04.1 LTS",
    "kernel_release": "6.8.0-45-generic",
    "architecture": "amd64",
    "virtualization": "kvm",
    "system_vendor": "QEMU",
    "product_name": "Standard PC (q35 + ICH9, 2009)",
    "ipv4": ["10.0.0.7"],
    "macs": ["52:54:00:ab:cd:ef"]
  },

  "scan": {                                  // how the scan was performed
    "started_at": "2024-03-09T14:05:06Z",
    "finished_at": "2024-03-09T14:05:41Z",
    "duration_ms": 35012,
    "root": "/",
    "excluded": ["./proc/**", "./sys/**", "./home/**"],
    "catalogers": ["installed", "directory"],
    "ran_as_root": true,
    "incomplete": false,
    "warnings": ["312 files could not be identified"]
  },

  "delta": {                                 // only with --since
    "since": "/var/lib/swinv/web-01-latest.json",
    "baseline_at": "2024-03-08T14:05:06Z",
    "baseline_host": "web-01",
    "added":   [ { "name": "curl", "version": "7.88.1-10", "type": "deb" } ],
    "removed": [ { "name": "zlib1g", "version": "1:1.2.13.dfsg-1", "type": "deb" } ],
    "changed": [ { "name": "openssl", "type": "deb",
                   "from_version": "3.0.11-1~deb12u2",
                   "to_version": "3.0.14-1~deb12u3",
                   "purl": "pkg:deb/debian/openssl@3.0.14-1~deb12u3" } ]
  },

  "components": [                            // the inventory itself
    {
      "name": "openssl",
      "version": "3.0.13-0ubuntu3.4",
      "type": "deb",
      "purl": "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.4?arch=amd64&distro=ubuntu-24.04",
      "cpes": ["cpe:2.3:a:openssl:openssl:3.0.13-0ubuntu3.4:*:*:*:*:*:*:*"],
      "licenses": ["Apache-2.0"],
      "locations": ["/var/lib/dpkg/status"],
      "found_by": "dpkg-db-cataloger"
    }
  ]
}
```

`tool`, `host`, `scan` and `components` are always present. `delta` appears only
with `--since`. `components` is always an array - an empty inventory writes
`[]`, never `null`.

### `tool`

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Always `"swinv"`. |
| `version` | string | Set at build time via `-ldflags`. |
| `commit` | string | Build commit; omitted if not set. |
| `syft_version` | string | The Syft version compiled in, read from `debug.ReadBuildInfo()`. This is what actually did the cataloging. |

### `host`

Machine identity, gathered by `internal/hostfacts` by reading kernel interfaces
directly - never by shelling out to `hostnamectl`, `dmidecode`, `ip`, or
`uname`. **Every field except `hostname` is optional**: an unreadable source
yields an omitted field, not an error and not a log line.

| Field | Source | Notes |
|---|---|---|
| `hostname` | `os.Hostname()`, or `<root>/etc/hostname` under `--root` | Always present. |
| `fqdn` | Reverse/CNAME lookup on the primary IP | Best-effort, ≤2 s, never fatal. Skipped when the root is not `/`. |
| `machine_id` | `/etc/machine-id`, falling back to `/var/lib/dbus/machine-id` | The stable fleet-wide machine key. `--require-host-id` makes it mandatory. |
| `boot_id` | `/proc/sys/kernel/random/boot_id` | Changes on every reboot; useful for telling two scans of one boot apart. |
| `os_id` | `/etc/os-release` `ID`, or Syft's distro detection when populated | e.g. `ubuntu`, `debian`, `rhel`. |
| `os_version_id` | `/etc/os-release` `VERSION_ID` | e.g. `24.04`. |
| `os_pretty_name` | `/etc/os-release` `PRETTY_NAME` | e.g. `Ubuntu 24.04.1 LTS`. |
| `kernel_release` | `/proc/sys/kernel/osrelease` | |
| `architecture` | `runtime.GOARCH` | `amd64`, `arm64`. |
| `virtualization` | DMI + `/sys/hypervisor/type`, plus container detection via `/.dockerenv` and `/proc/1/cgroup` | Best-effort; empty is normal on bare metal. |
| `system_vendor` | `/sys/class/dmi/id/sys_vendor` | |
| `product_name` | `/sys/class/dmi/id/product_name` | |
| `product_serial` | `/sys/class/dmi/id/product_serial` | **Root-only.** Silently empty for a non-root run. |
| `product_uuid` | `/sys/class/dmi/id/product_uuid` | **Root-only.** Silently empty for a non-root run. |
| `ipv4`, `ipv6`, `macs` | `net.Interfaces()` | Arrays, sorted. Loopback, down interfaces, and link-local addresses are skipped. |

Firmware placeholder strings (`To Be Filled By O.E.M.`, `Default string`,
`System Serial Number`, the all-zero UUID) are mapped to empty, because they
look like real data once a fleet is aggregated.

### `scan`

| Field | Type | Meaning |
|---|---|---|
| `started_at` | RFC 3339 UTC | Scan start. This is the value used as `scanned_at` in CSV and NDJSON, and as the CycloneDX `metadata.timestamp`. |
| `finished_at` | RFC 3339 UTC | Scan end. |
| `duration_ms` | int | Wall time in milliseconds. |
| `root` | string | The `--root` that was scanned. |
| `excluded` | []string | The **final** exclusion list actually applied: defaults, auto-excluded non-local mounts, `--exclude` additions, and any symlinks quarantined by the preflight. Omitted if empty. |
| `catalogers` | []string | The cataloger selection in effect. Omitted if empty. |
| `ran_as_root` | bool | `false` for an unprivileged run, which is fully supported and never an error. |
| `incomplete` | bool | `true` if any cataloger errored. The output is still written; the exit code is 1. **Check this before trusting a thin inventory.** |
| `warnings` | []string | Human-readable notes: non-root, skipped home directories, unidentified-file counts, quarantined symlinks, shared evidence files not hashed, a `--since` baseline from another machine. Omitted if empty. |

`incomplete` plus `warnings` is how you tell a machine that genuinely has little
software from a scan that went wrong.

### `components`

One entry per distinct piece of installed software.

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Package name as the ecosystem spells it. Always present. |
| `version` | string | Version string, verbatim. Not normalised, not parsed. Always present. |
| `type` | string | Ecosystem: `deb`, `rpm`, `apk`, `python`, `npm`, `go-module`, `java-archive`, `binary`, … Always present. |
| `language` | string | Ecosystem language where one applies (`python`, `javascript`, `go`). Omitted for OS packages. |
| `purl` | string | Package URL. **The canonical identifier** - see below. Omitted only when Syft supplies none. |
| `cpes` | []string | Candidate CPEs, sorted. Syft generates several per package; all are kept. |
| `licenses` | []string | Licence strings, sorted. SPDX identifiers where the ecosystem provides them, free text where it does not (`Apache 2.0` from a Python `METADATA` is a real example). Not validated against the SPDX list. |
| `locations` | []string | Real absolute paths on the scanned machine, sorted, with the `--root` prefix stripped. For a deb this is usually `/var/lib/dpkg/status`; for a Python package the `dist-info` files. |
| `found_by` | string | The originating Syft cataloger, e.g. `dpkg-db-cataloger`. Useful when a result looks wrong. |
| `sha256` | string | Hex digest of the component's primary on-disk file. **Only with `--hash`**, and only for files backing exactly one component - see below. |
| `change` | string | `added` or `changed` for a component that moved since the `--since` baseline; absent for unchanged components and for runs without `--since`. `removed` appears only in `--delta-only` output, since a removed component is by definition not in the current inventory. |

#### `--hash` and shared evidence files

`--hash` digests each component's primary file. **Files that back more than one
component are deliberately skipped**: most debs cite `/var/lib/dpkg/status` as
their evidence, so digesting it would give every package on the machine an
identical hash *and* make all of them appear changed whenever any single package
changed - precisely backwards for change detection. The count skipped is
reported in `scan.warnings`:

```
1 shared evidence file(s) such as package databases were not hashed;
a digest of a file backing many components identifies none of them
```

Files above 512 MiB and anything that is not a regular file are also skipped. So
in practice OS packages have no `sha256` and language packages do.

### `services`

Schema 1.6. One entry per listening process, plus at most one aggregate entry
for sockets that could not be attributed to a process at all. Linux only -
see [docs/SERVER-ROLES.md](SERVER-ROLES.md).

```jsonc
"services": [
  {
    "endpoints": ["0.0.0.0:22/tcp", "[::]:22/tcp6"],
    "pid": 811,
    "executable": "/usr/sbin/sshd",
    "command": "sshd: /usr/sbin/sshd -D [listener]",
    "unit": "ssh.service",
    "user": "0",
    "components": ["pkg:deb/ubuntu/openssh-server@1:10.2p1-2ubuntu3.5"],
    "confidence": "high",
    "evidence": [
      "socket 0.0.0.0:22/tcp held by pid 811",
      "executable /usr/sbin/sshd",
      "systemd unit ssh.service",
      "the package database records pkg:deb/ubuntu/openssh-server@... as owning this file"
    ]
  }
]
```

| Field | Type | Meaning |
|---|---|---|
| `endpoints` | []string | What it accepts on, as `address:port/protocol`. |
| `pid` | int | The listening process. Omitted where there is none. |
| `executable` | string | The path **as it exists in that process's mount namespace**, which for a containerised process need not exist on this host. |
| `command` | string | The process's `argv`. Omitted with `--no-service-command`; see [SECURITY.md](../SECURITY.md), because command lines carry secrets. |
| `unit` | string | The owning systemd unit, from the process's cgroup. |
| `container` | string | The container id, when the process runs in one. |
| `user` | string | The numeric uid the process runs as. |
| `socket_activated` | bool | `init` holds the socket, not the service. The daemon may not be running at all. |
| `components` | []string | The installed software behind it, by PURL where one exists and `name@version` otherwise. **Empty means nothing installed owns the executable** - which is the interesting case. |
| `confidence` | string | `high`, `medium` or `low`; see below. |
| `evidence` | []string | What produced the finding, in the order it was established. |

#### Confidence is recorded, not implied

A service finding is assembled from evidence of varying strength, and a single
field claiming "port 443 is nginx 1.24" is indistinguishable from a guess by
the time it reaches anyone.

| `confidence` | What was established |
|---|---|
| `high` | The process was identified and an installed package's own file list claims its executable. Product and version are known. |
| `medium` (Windows, install directory) | The executable sits under a directory an installed product recorded as its `InstallLocation`. Weaker than a package's own file list - the product was installed there, which is not the same as it shipping this file - and graded as such. This is the only join available on Windows, where the registry records directories and never executables. |
| `medium` | The process was identified, but **nothing installed owns its executable** - so it was not installed by a package manager. Not a weaker observation: this is the finding a package inventory alone cannot produce. Also used for a containerised process, whose executable path belongs to the container's filesystem and must not be matched against this host's packages. |
| `low` | Something is listening and the process behind it could not be identified: the scan lacked the privilege to read another user's open files, or `init` holds the socket. |

#### How the attribution works

The join is from a listening executable's path to the package that installed
it, and it comes from the **package databases' own file lists** - `dpkg`,
`rpm`, `apk`, `pacman` - not from `component.locations`. A deb's locations are
its evidence files (`/var/lib/dpkg/status`, its own `.list`), never
`/usr/sbin/sshd`, so a naive join finds nothing and reports every daemon on a
stock server as unmanaged software.

Those file lists run to hundreds of thousands of paths on a normal server, so
swinv does not index them. It takes the socket snapshot **before** the scan,
hands the scan the few dozen executable paths it actually needs answered, and
the catalogers check membership as they go. A path that was not probed and a
path that no package owns are kept distinguishable.

Where the package databases say nothing, a component that recorded the exact
path as one of its own locations is used instead - which is what a Windows
registry entry naming its own executable looks like.

### `exposure`

Schema 1.7. One entry per listening socket **in the host network namespace**,
and nothing else.

On Linux this comes from `/proc`; on Windows from `iphlpapi`'s
`GetExtendedTcpTable`/`GetExtendedUdpTable`, which return the tables with an
owning pid already attached.

```jsonc
"exposure": [
  {
    "address": "0.0.0.0", "port": 80, "protocol": "tcp", "family": "ipv4",
    "bind_scope": "wildcard",
    "pid": 2562, "executable": "/usr/bin/docker-proxy", "unit": "docker.service",
    "backend": {
      "address": "172.18.0.2", "port": 80,
      "container": "9d5a98d0dc04…", "executable": "/usr/sbin/nginx",
      "via": "docker-proxy-argv"
    },
    "image": {
      "ref": "nginxinc/nginx-unprivileged:1.27-alpine",
      "manifest_digest": "sha256:…", "id": "sha256:…",
      "purl": "pkg:oci/nginx-unprivileged@sha256%3A…?repository_url=…&tag=1.27-alpine"
    },
    "components": ["pkg:apk/alpine/nginx@1.27.5-r1?arch=x86_64&distro=alpine-3.21.3"],
    "confidence": "high",
    "evidence": ["socket 0.0.0.0:80/tcp held by pid 2562 in the host network namespace", "…"]
  }
]
```

**Membership is the verdict.** A socket bound to `0.0.0.0` inside a container's
network namespace is not reachable at this machine's addresses, and if such a
row sat in this array next to an address, a reader would conclude the opposite.
So those rows are not here at all - they are in [`containers`](#containers) -
and a consumer reading only this array cannot get it wrong.

One row per **bound endpoint**, not per process and not per socket handle,
because that is the unit of the question: a process bound to four addresses can
be four different answers, three on loopback and one on the world, while twenty
handles on the same address and port are one open port. A socket held by two
processes - `init` and the daemon it socket-activated - is one row too, and the
one kept is the row that names the daemon. Where two genuinely different
programs share a UDP port, both identities are kept.

| Field | Meaning |
|---|---|
| `address`, `port`, `protocol` | The bind, verbatim. `protocol` is `tcp` or `udp`. |
| `family` | `ipv4` or `ipv6`, taken from the table the socket was read from - Go renders an IPv4-mapped address as a dotted quad, so the text of `address` is not reliable for this. |
| `bind_scope` | `wildcard`, `loopback`, `link_local`, or `specific`. See below. |
| `wildcard_covers_ipv4` | A `::` bind on a kernel with `bindv6only` off accepts IPv4 too. Without this a consumer counting IPv4 exposure by family undercounts. |
| `pid`, `executable`, `unit`, `user` | The process holding the socket. All are absent when the holder could not be identified - the socket is still reported, because "something is listening on 443 and I could not see what" is the statement this section exists to make. |
| `container` | Set when the *holding* process is containerised - a `--network=host` container or a `hostNetwork` pod. |
| `os_component` | The listener is part of the operating system itself. Set on Windows for anything under `%SystemRoot%`, which swinv represents by the installed servicing updates rather than file by file. **Filter it out before treating `medium` as "unmanaged software"**, or every Windows host contributes several dozen false entries. Never set on Linux, where the OS's own binaries are package-owned like any other. |
| `processes` | How many sockets were found bound to this endpoint, when more than one was. A browser opens twenty on `0.0.0.0:5353` for mDNS; as exposure that is one open port, so the rows are folded and this records how many were folded. |
| `backend` | Where a forwarded port leads. See below. |
| `image` | The container image behind a forwarded port. **A locator, not an identity** - see [`containers`](#containers). |
| `components` | The software behind this endpoint, by PURL. For a forwarded port this is the package **inside the container**, never the forwarding process's own. |
| `confidence`, `evidence` | As for services. |

#### `bind_scope` is about the bind, not about reachability

| Value | Meaning |
|---|---|
| `wildcard` | `0.0.0.0` or `::` - every address the host has now, and every one added tomorrow by a new interface. |
| `loopback` | `127.0.0.0/8` or `::1`. |
| `link_local` | `169.254.0.0/16` or `fe80::/10`. |
| `specific` | One particular address, which is kept verbatim in `address`. |

There is deliberately no `public` and no `private`, and nothing anywhere in
this document says "internet-facing". **swinv reads no firewall, no NAT table
and no cloud security group.** It cannot tell a lab bridge from a flat
datacentre L2 where every host reaches every address, and a `private` verdict
would be read as "therefore safe". The address is always in the row, so a
consumer with an actual network model can classify it; the reverse is not
possible.

`scan.firewall_examined` is emitted as a constant `false` for the same reason,
and repeats on every row of the exposure CSV - a consumer's ingest pipeline
never sees prose.

#### `backend`: following a published port

A published container port is held on the host by a forwarding process. Its own
package is not the answer: reporting `pkg:deb/ubuntu/docker-ce` as the software
behind port 3000 is true and useless, and it was 14 of 31 services on the
development host. So a recognised forwarder - `docker-proxy`, `rootlessport`,
`slirp4netns`, `pasta` - **never** contributes its own attribution, and the
identity comes from the container behind it instead.

The container is found by matching the forward's destination address against
the addresses assigned inside each container's namespace, falling back to the
port when exactly one container listens on it. Several containers publishing
8080 is ordinary, so an ambiguous match resolves to *nothing* rather than to a
coin flip presented as a finding.

**`via` says how the forward was learned**, and `docker-proxy-argv` means it
came from that process's command line. This is enrichment, never discovery:
`docker-proxy` does not exist at all when the daemon runs with
`"userland-proxy": false`, under rootless Docker, or under rootful Podman's
default netavark - see the blind spots below.

### `containers`

Schema 1.7. One entry per containerised workload, and what each is listening on
**inside its own network namespace**. Root-only in practice.

The two platforms reach this differently, and they reach different depths.

On **Linux** the container's processes are visible on the host, so swinv reads
the container's own package database through `/proc/<pid>/root` and names the
software. No daemon is involved.

On **Windows** none of that is possible. A Docker Desktop container is a Linux
process inside a WSL2 virtual machine: it has no entry in the Windows process
table, its sockets live in a namespace inside that VM, and no Windows API
reaches either. So swinv asks the local Docker engine over its named pipe -
the one place it talks to a daemon, taken because the alternative is a wrong
answer rather than a missing one. It is still true that no network activity
occurs: a named pipe is kernel IPC with no address and no route.

The engine gives the container, the image, the entrypoint and the exact
published port mappings - better than anything derivable from a forwarding
process's command line, and used in preference to it on any platform where a
runtime supplies them. What it cannot give is the packages inside the
container, so those services are reported at `medium` with the workload and
image named, and `container-packages-not-readable` appears in the blind spots.
To get package identity for a container on a Windows host, run swinv inside
the container host itself.

```jsonc
"containers": [
  {
    "id": "9d5a98d0dc04…", "name": "notprem", "runtime": "docker",
    "image": {"ref": "nginxinc/nginx-unprivileged:1.27-alpine", "manifest_digest": "sha256:…"},
    "os_id": "alpine", "os_version_id": "3.21.3",
    "pod": {"name": "web-7d4f", "namespace": "default", "container": "nginx"},
    "services": [{
      "endpoints": ["0.0.0.0:8080/tcp"],
      "executable": "/usr/sbin/nginx",
      "processes": 9,
      "components": ["pkg:apk/alpine/nginx@1.27.5-r1?arch=x86_64&distro=alpine-3.21.3"],
      "confidence": "high",
      "published_as": ["0.0.0.0:80/tcp"]
    }]
  }
]
```

**Nothing in here is a host-reachability claim.** A container port reaches this
machine only if something published it, and that fact lives in `exposure`,
cross-linked from `published_as`.

`state` is the runtime's own word - `running`, `exited`, `created`. **Stopped
containers are included, and contribute no exposure rows**: they serve nothing,
but they are software present on the machine, an image with a known CVE does
not stop having it because the container is down, and it will be up again.

`declared_endpoints` are the ports the image (`EXPOSE`) or the run
configuration (`-p`) says the container serves on. **A declaration, never an
observation** - for a stopped container it is the only network fact available.
What is actually reachable on this host is in `exposure` and nowhere else.

Containers with no network endpoint at all, declared or observed, are left out.
A build container with no ports is not part of this machine's attack surface,
and reading its filesystem would cost without answering anything.

`os_id` and `os_version_id` come from the container's *own* `/etc/os-release`.
This is not decoration: a container is a different operating system from its
host - one on the development machine is RHEL 8.10 on an Ubuntu 26.04 server -
and that is what decides which advisories apply to its packages.

`processes` folds a prefork server back into one service. nginx's master and
its eight workers all hold the same inherited socket; reporting nine services
would misstate both what is running and how much of it, and repeat the same
identity nine times in every downstream count.

#### How container services get a usable identity

The `components` PURL comes from the **container's own package database**, by
one of two routes with different precision.

**Through `/proc/<pid>/root`**, probed only for the executables that are
actually listening - the same discipline the host join uses, one namespace
over. Precise, needs no daemon, and gives the package behind a *specific*
listening process. Linux, running containers only.

**Through the container runtime's archive endpoint**, which returns a file
from a container's filesystem whether or not it is running. This is the only
route for a stopped container, and the only route for any container on
Windows, where a Docker Desktop container is a Linux process inside a virtual
machine that no Windows API reaches. It gives the container's *whole* package
list rather than the owner of one executable, because there is no process to
ask about - a weaker statement, and marked as such by
`attributes.scan_scope = "container-package-database"` on each component.

`dpkg`, `apk` and `rpm` are read by both routes. Where the first route already
answered, the second leaves it alone: naming the package behind a listening
executable beats listing the two hundred packages that share its filesystem.

An empty `components` is the interesting case, not a failure: it is software
that was unpacked into the image rather than installed by its package manager,
which is most application containers.

**The image reference is a locator, not an identity a matcher can use.** There
is no `oci` matcher in Grype, no OCI coordinates in OSV or OSS Index, and
Dependency-Track will ingest an image PURL, find nothing, and display the
component as clean - which is indistinguishable from "analysed and safe". So
`image` never appears in any `components` list. Use it to join to an image scan
you perform elsewhere; that is what actually produces findings for an image.
Note that `manifest_digest` is the registry manifest digest, which is what
`repo@sha256:…` means and what an image scanner will have seen, while `id` is
the local config digest - a different value, and confusing the two is the
classic bug here.

#### Container packages join `components[]`

Each package found this way is also added to the main `components` array with
`root: "container:<short-id>"`, so that CVE tooling reading `components[]` and
nothing else - which is most of it, `grype sbom:` included - sees them at all.

Every such row carries an `attributes.scan_scope` saying how it was found:

| `scan_scope` | Meaning |
|---|---|
| `listening-executables-only` | Only the packages owning a listening executable were probed. **Not a container inventory** - a precise answer to a narrow question. |
| `container-package-database` | The container's whole package database, read through the runtime. A complete list of what that container contains, with no claim about which of it is serving. |

Each also carries `container_id`, `container_name`, `container_state` and the
image reference and digest, so a consumer can tell a package in a running
container from one in a stopped image.

### `scan.exposure_blind_spots`

Schema 1.7. What this scan could not observe, in machine-readable form.

```json
"firewall_examined": false,
"exposure_blind_spots": ["netfilter-dnat-not-read", "firewall-rules-not-read"]
```

**This is the most important field in the exposure section.** Without it, a
host running Docker with `userland-proxy` disabled - where publishing is pure
netfilter DNAT and no process holds a socket - produces a document identical to
a host with nothing exposed at all. A consumer must be able to tell "looked and
found nothing" from "could not look", and warning strings do not survive an
ingest pipeline.

| Identifier | Meaning |
|---|---|
| `netfilter-dnat-not-read` | Always present on Linux. A port published by a DNAT rule with no process behind it has no listening socket, and no `/proc` interface reveals one. This covers **Kubernetes NodePort** in iptables and IPVS mode, Docker with `userland-proxy` disabled, rootful Podman's default netavark, and any hand-written rule. |
| `firewall-rules-not-read` | Always present. Nothing here reads a firewall, so no row is a statement about reachability. |
| `process-owners-not-readable-unprivileged` | The scan was not root, so most sockets could not be attributed and container namespaces could not be enumerated. |
| `kubernetes-node-nodeport-not-observable` | Kubelet state is present. A node reporting six endpoints is not a small attack surface, it is a partially observed one. |
| `docker-userland-proxy-disabled` | Read from `/etc/docker/daemon.json`. Every published port on this machine is a netfilter rule that this scan cannot see. |
| `container-packages-not-readable` | Containers are running and were identified, but their filesystems could not be read, so the packages inside them are unknown. Normal on Windows, where the container's filesystem is inside a virtual machine. The image is reported, and an image reference is not something a vulnerability matcher resolves. |

swinv does **not** parse iptables, nftables or IPVS. Doing so would mean
netlink or shelling out, would still miss eBPF-based implementations, and -
decisively - would not answer the reachability question even when it succeeded,
because that depends on chain policies, `ct state` matches, ipsets, interface
constraints, and whatever sits in front of the NIC. Trading a declared blind
spot for an undeclared guess is the wrong trade. For a Kubernetes fleet, the
API server answers this correctly in one call, with service names.

---

## Identity and ordering - the guarantees consumers rely on

These are not implementation details. They are the contract that makes these
files joinable and diffable, and they are enforced by
`model.Normalize`/`model.Less` and covered by tests.

**1. PURL is the canonical join key.** Package URLs are the identifier to join
on across machines - they encode ecosystem, namespace, name, version, and
qualifiers in one string. `swinv` populates `purl` whenever Syft provides one.
Join on `name` alone at your peril: `python3-requests` the deb and `requests`
the PyPI package are different rows and should stay that way.

**2. Deduplication on `(name, version, type, purl)`.** Syft can legitimately
report the same package from two catalogers. Those reports are merged into one
component:

- **Multi-valued fields are unioned:** `cpes`, `licenses`, `locations`.
- **Single-valued fields take the first non-empty value:** `language`,
  `found_by`, `sha256`. "First" means first in the deduplicated input order, not
  first to finish, so the result does not depend on cataloger completion order.

**3. Deterministic sort.** Components are sorted by `type`, then `name`, then
`version`, then `purl`. Every string slice - `locations`, `cpes`, `licenses`,
`ipv4`, `ipv6`, `macs`, `excluded` - is sorted and deduplicated too.

**4. Two runs on an unchanged machine are byte-identical apart from the
timestamps in `scan`.** Nothing in the output path reads the wall clock,
generates a random identifier, or iterates a map without sorting it first. This
holds across all four formats, and it is what makes daily inventory files worth
keeping on disk:

```sh
diff <(jq 'del(.scan)' yesterday.json) <(jq 'del(.scan)' today.json)
```

---

## The delta block (`--since`)

`--since previous.json` compares this scan against an earlier `swinv` JSON
report and adds a `delta` block. By default the full inventory is still written
alongside it, so the file remains a self-contained inventory that can itself
serve as tomorrow's baseline.

```json
"delta": {
  "since": "/var/tmp/baseline.json",
  "baseline_at": "2026-08-19T11:35:35Z",
  "baseline_host": "web-01",
  "added": [
    { "name": "left-pad", "version": "1.3.0", "type": "npm",
      "language": "javascript", "purl": "pkg:npm/left-pad@1.3.0",
      "licenses": ["WTFPL"],
      "locations": ["/srv/app/node_modules/left-pad/package.json"],
      "found_by": "javascript-package-cataloger" }
  ],
  "removed": [
    { "name": "curl", "version": "7.88.1-10", "type": "deb",
      "purl": "pkg:deb/debian/curl@7.88.1-10" }
  ],
  "changed": [
    { "name": "openssl", "type": "deb",
      "from_version": "3.0.9-1",
      "to_version": "3.0.11-1~deb12u2",
      "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12" }
  ]
}
```

| Field | Meaning |
|---|---|
| `since` | The baseline path exactly as passed on the command line. |
| `delta_only` | Present and `true` only when `--delta-only` was used. Marks `components` as holding just the diff. |
| `baseline_at` | The baseline's `scan.started_at`. |
| `baseline_host` | The baseline's hostname, so an accidental cross-machine comparison is visible rather than silent. |
| `added` | Full `Component` objects, present now and absent from the baseline. |
| `removed` | Full `Component` objects as they appeared **in the baseline**, including the version they had then. |
| `changed` | `Change` objects: `name`, `type`, `from_version`, `to_version`, and `purl` (the current one). |

`added`, `removed` and `changed` are omitted when empty, and each is sorted the
same way as `components`.

### Matching is on `(name, type)`, not version

This is the point of the feature. An upgraded package must read as **one
`changed` entry**, not as a removal plus an unrelated addition - otherwise a
daily diff of a machine that patched twenty packages reports forty events and
tells you nothing about which version moved to which.

### `--delta-only`

`--delta-only` drops the unchanged components, so `components` holds just the
diff with each entry tagged in `change`:

```json
"components": [
  { "name": "curl",     "version": "7.88.1-10",        "type": "deb", "change": "removed" },
  { "name": "openssl",  "version": "3.0.11-1~deb12u2", "type": "deb", "change": "changed" },
  { "name": "left-pad", "version": "1.3.0",            "type": "npm", "change": "added"   }
]
```

A `removed` entry keeps the version it had in the baseline; a `changed` entry
carries the **current** version, with the previous one available in
`delta.changed[].from_version`.

Such a report sets `delta.delta_only`, records a warning, and is **refused as a
future `--since` baseline** with exit code 2. Diffing against a diff would
report every unchanged package on the machine as newly added.

Comparing against a *different* machine's report is permitted, but recorded in
`scan.warnings`. Any schema version is accepted as a baseline, so a delta still
works across a `swinv` upgrade.

---

## CSV

One row per component. Host identity is repeated on every row, so the file stays
useful standalone and rows from many machines can simply be concatenated.

- **RFC 4180 quoting.** Values containing `,`, `"`, or a newline are quoted and
  internal quotes doubled.
- **`\n` line endings** (RFC 4180 permits CRLF; `\n` is what Unix consumers
  expect and it keeps the bytes stable).
- **UTF-8, no BOM.**
- **The header row is always present**, including for a report with zero
  components.

### The 20 columns, in exactly this order

```
hostname,machine_id,os_id,os_version_id,architecture,scanned_at,name,version,type,language,purl,cpes,licenses,locations,found_by,sha256,change
```

| # | Column | Source |
|---|---|---|
| 1 | `hostname` | `host.hostname` |
| 2 | `machine_id` | `host.machine_id` |
| 3 | `os_id` | `host.os_id` |
| 4 | `os_version_id` | `host.os_version_id` |
| 5 | `architecture` | `host.architecture` |
| 6 | `scanned_at` | `scan.started_at`, RFC 3339 in UTC |
| 7 | `name` | `component.name` |
| 8 | `version` | `component.version` |
| 9 | `type` | `component.type` |
| 10 | `language` | `component.language` |
| 11 | `purl` | `component.purl` |
| 12 | `cpes` | `component.cpes`, joined with `;` |
| 13 | `licenses` | `component.licenses`, joined with `;` |
| 14 | `locations` | `component.locations`, joined with `;` |
| 15 | `found_by` | `component.found_by` |
| 16 | `sha256` | `component.sha256` (schema 1.1) |
| 17 | `change` | `component.change` (schema 1.1) |
| 18 | `vendor` | `component.vendor` (schema 1.2) |
| 19 | `root` | `component.root` (schema 1.4) |
| 20 | `owned_by` | `component.owned_by` (schema 1.5) |

A real row, from the test fixture:

```csv
hostname,machine_id,os_id,os_version_id,architecture,scanned_at,name,version,type,language,purl,cpes,licenses,locations,found_by,sha256,change
fixture-host,0123456789abcdef0123456789abcdef,debian,12,amd64,2024-01-02T03:04:05Z,openssl,3.0.11-1~deb12u2,deb,,pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12,cpe:2.3:a:openssl:openssl:3.0.11-1\~deb12u2:*:*:*:*:*:*:*,,/var/lib/dpkg/status,dpkg-db-cataloger,,
```

### Multi-valued fields

`cpes`, `licenses` and `locations` are joined with `;` **inside** their single
CSV field. The separator is deliberately not a comma, so a licence field such as
`GPL-2.0, MIT` stays in its own column rather than shifting every column to its
right. Split on `;` after parsing the CSV, never before.

### `sha256` and `change` are always present

Both columns are emitted **even when `--hash` and `--since` were not used** -
empty, but present. The column shape therefore never varies with the flags a
given host happened to run with. That is what keeps CSVs concatenable across
machines and across runs, and it is why they must not be made conditional.

### The services sidecar

When `--format` includes `csv` and services were collected, a second file is
written alongside the component CSV with `-services` before the extension:

```
web-01-20240309.csv            components
web-01-20240309-services.csv   what is listening
web-01-latest-services.csv     symlink, with --latest-symlink
```

A sidecar rather than extra columns, for the same reason `services` is a
top-level array in the JSON: a component appears once, a service appears once
per listening process, and wedging them together would give every inventory row
fourteen empty columns. A sidecar rather than a `--format` of its own, because
an operator asking for CSV wants the whole run as CSV, and making them name a
second format to get half of it is a trap.

**20 columns, in exactly this order:**

```
hostname,machine_id,os_id,os_version_id,architecture,scanned_at,endpoints,pid,executable,command,unit,container,user,socket_activated,components,confidence,evidence,processes,published_as,os_component
```

`processes`, `published_as` and `os_component` were appended in schema 1.7, at the end, so a
1.6 row stays a prefix of a 1.7 row and a consumer reading by position keeps
working.

The first six are the same host identity the component CSV repeats, for the
same reason. `endpoints`, `components` and `evidence` are multi-valued and are
joined with `;` inside their single field. `pid` is empty rather than `0` on the
aggregate row: `0` is a real pid and would read as a claim. The header is always
present.

### The exposure sidecar

Schema 1.7. A third file, written alongside the other two whenever `--format`
includes `csv` and exposure was collected:

```
web-01-20240309-exposure.csv
web-01-latest-exposure.csv
```

**One row per listening socket in the host network namespace**, which is the
unit of work for a system whose job is the network edge: "is this port a
problem" is a question about a port, not about a process.

**32 columns:**

```
hostname,machine_id,os_id,os_version_id,architecture,scanned_at,address,port,protocol,family,bind_scope,wildcard_covers_ipv4,pid,executable,unit,user,container,os_component,processes,backend_address,backend_port,backend_container,backend_executable,backend_via,image_ref,image_manifest_digest,components,confidence,evidence,ran_as_root,firewall_examined,exposure_blind_spots
```

The last three repeat the scan-level qualifiers on **every row**, deliberately.
A denormalised consumer never sees the `scan` block, and without them it cannot
tell a complete row from one produced by a scan that could not look. A natural
key for deduplicating across scans is `machine_id + address + port + protocol`.

`--stdout` has no sidecars - there is only one stream - so `--stdout --format
csv` gives the components alone. Use `--stdout --format json` if you want the
services, containers or exposure blocks on a pipe.

The file is written whenever services were collected at all, even when nothing
was listening - a header with no rows says "we looked and found nothing", which
a missing file does not. It is **not** written when services were never
collected: on Windows, with `--no-services`, or when `--root` is not `/`.

---

## NDJSON

One JSON object per component, one per line, no indentation, a newline after
every record. A report with no components produces an empty file, which is the
correct empty document for this format.

Each line repeats the host identity and the scan time alongside the component
fields, using the same `snake_case` names and the same order as the CSV columns,
so a single line is self-describing when it arrives at a log pipeline with no
surrounding context.

**NDJSON carries components by default**, and can be asked for more. Every line
was one component before schema 1.9, so every extra record type is opt-in via
`--ndjson-include` and carries a `record_type` a consumer can skip. A line with
no `record_type` is a component.

| `--ndjson-include` | Emits | `record_type` |
|---|---|---|
| `exposure` | one record per open port **per package behind it** | `exposure` |
| `containers` | one record per container, running or stopped | `container` |
| `links` | one record per (binary, library it loads) | `link` |
| `all` | all three | |

Services are still not represented; `exposure` carries the same facts in the
shape a stream consumer wants. Use JSON, the services CSV, or CycloneDX for the
`services` block itself.

#### `exposure` records

```json
{"record_type":"exposure","hostname":"web01","scanned_at":"2026-08-23T06:18:41Z",
 "address":"0.0.0.0","port":22,"protocol":"tcp","family":"ipv4","bind_scope":"wildcard",
 "purl":"pkg:deb/ubuntu/openssh-server@1%3A10.2p1-2ubuntu3.5?arch=amd64&distro=ubuntu-26.04",
 "executable":"/usr/sbin/sshd","unit":"ssh.service","user":"0","processes":2,
 "confidence":"high"}
```

**Denormalised on purpose**: a port served by three packages produces three
records, so a vulnerability finding joins on the package alone without the
consumer unpacking an array.

**A port with nothing attributed still gets a record**, with no `purl`. A port
answering with no package behind it is a gap in what can be seen, not a port
that is safe, and dropping it here would hide it completely.

A published container port carries `container_id` and `container_name`, and its
`executable` is the process **inside** the container rather than the forwarder.
`os_component` marks a listener that is part of the operating system, which on
Windows is most of them - filter it before treating an unattributed port as
interesting.

#### `container` records

One per container, **including stopped ones**: a stopped container is one
`docker start` from a running one, so its vulnerabilities are latent rather
than absent. A consumer can rank them last; it cannot invent them.

```json
{"record_type":"container","hostname":"web01","scanned_at":"2026-08-23T06:18:41Z",
 "container_id":"2fa4c621fb08…","container_name":"argilla-elasticsearch-1",
 "runtime":"docker","state":"exited",
 "image_ref":"docker.elastic.co/elasticsearch/elasticsearch:8.17.0",
 "image_digest":"sha256:2f6025…","image_purl":"pkg:oci/elasticsearch@sha256%3A2f6025…",
 "os_id":"ubuntu","os_version_id":"20.04",
 "declared_endpoints":["9200/tcp","9300/tcp"],
 "declared_endpoints_text":"9200/tcp;9300/tcp","n_declared_endpoints":2,
 "endpoints":["9200/tcp","9300/tcp"],"endpoints_text":"9200/tcp;9300/tcp","n_endpoints":2}
```

`os_id` and `os_version_id` are the container's own, which is what its packages
must be matched against - a Debian 12 container on an Ubuntu host is Debian.

#### Two shapes chosen for streaming consumers

**No field is ever `null`; absent fields are omitted.** Splunk indexes a JSON
`null` as the four-character *string* `"null"`, so `"unit": null` would give
every listener on the host a systemd unit named `null`, and `coalesce(unit,
executable)` could not tell the difference.

**Arrays come with a flattened twin.** Splunk's JSON extraction renames an
array field with a `{}` suffix, so a search asking for `endpoints` silently
gets nothing - which once reported a whole fleet as publishing no ports. Every
array field therefore also has `_text` (`;`-joined) and `n_` (count) forms.

#### With `--heartbeat`

Exposure and container records are **still emitted on an unchanged scan**. The
heartbeat suppresses the components, which are the volume; what is listening
can change while the installed software does not - a port opened, a container
started - so suppressing those too would make the heartbeat hide the
fastest-moving facts in the report. Both sections are a few dozen records
against many thousands of components.

### The heartbeat

Schema 1.9, with `--heartbeat` or `--transmit`. One extra record at the head of
the stream, and - when the inventory has not changed since the last scan - the
only record in it. Schema 1.10 turned it into a manifest; see
[the manifest](#the-manifest).

```json
{"record_type":"heartbeat","hostname":"web01","digest":"sha256:9f2c…",
 "n_components":14425,"scanned_at":"2026-08-22T06:47:35Z",
 "machine_id":"0123…","os_id":"ubuntu","os_version_id":"24.04","architecture":"amd64"}
```

**Why it exists.** Every scan restates the whole inventory, which is the right
shape for correctness - a package that disappears is genuinely gone rather than
merely unmentioned - and the wrong shape for volume. At 5,000 hosts averaging
14,000 components scanned hourly that is over a billion records a day, nearly
all identical to the day before. The heartbeat lets a consumer decide a host is
unchanged *before* reading any of its components.

| Field | Meaning |
|---|---|
| `record_type` | Literally `heartbeat`. **A record without this field is a component** - which is what every line was before this existed, so existing consumers are unaffected. |
| `digest` | Opaque. Compare it only against the previous value stored for the same host; never parse it, and never assume it is stable across swinv versions. |
| `n_components` | The real count, **even on a scan that sends none** - so a quiet host stays distinguishable from an empty one. |
| `machine_id`, `os_id`, `os_version_id`, `architecture` | Host identity, so a consumer's host record stays fed on a scan carrying no components. |

**Only NDJSON is affected.** JSON, CSV and CycloneDX carry the complete
inventory on every scan regardless. A CSV with no rows would be a false
statement about the machine; a heartbeat is a true one.

**Full lists on change, never deltas.** A delta cannot express a removal, and
"this package is no longer installed" is the fact that decides whether a
vulnerability is fixed or merely unreported. Sending the whole list on change
keeps that property while removing the volume.

### The manifest

Schema 1.10. The heartbeat record grew a description of what the stream it
heads actually contains.

```json
{"record_type":"heartbeat","hostname":"web01","digest":"sha256:9f2c…",
 "n_components":3993,"scanned_at":"2026-08-25T09:14:02Z",
 "machine_id":"0123…","os_id":"ubuntu","os_version_id":"26.04","architecture":"amd64",
 "schema_version":2,"scan_id":"6f423aa4-3fcc-4b11-ac7b-def75ba5a2e8",
 "swinv_version":"0.7.0","duration_ms":8412,
 "counts":{"component":3993,"exposure":50,"container":0},
 "sources":{"dpkg":{"status":"ok","components":3218},
            "javascript-package":{"status":"ok","components":512},
            "rpm":{"status":"skipped","components":0,
                   "reason":"no rpm package database on this host"}}}
```

**Why it exists.** A host whose collector wrote 3,993 components once arrived
at its consumer as 15, and every layer in between reported success: the
forwarder shipped the file, the indexer accepted the events, the matcher ran,
the dashboard showed a host reporting. The matcher was right that fifteen
packages contain no vulnerabilities. Nothing anywhere compared what arrived
against what was sent. Diagnosis took a day.

Two fields close that, and both are cheap.

| Field | What it is for |
|---|---|
| `counts` | The records **in this stream**, by type. A receiver that stores fewer than this has lost data and can say so in the same minute. |
| `sources` | What each enumeration source did: `ok`, `skipped` or `error`, with a `reason` for anything that is not `ok`. "Skipped because unreadable" and "found nothing" are different facts and were previously indistinguishable. |
| `scan_id` | Identifies this run. The idempotency key for `--transmit`, and the thing a support conversation names. |
| `schema_version` | `2` for this shape. Absent on the 1.9 heartbeat, so the two are told apart without a heuristic. |
| `swinv_version`, `duration_ms` | Which collector, and how long it took. |

**`counts.component` describes the stream; `n_components` describes the host.**
They are the same number on an ordinary scan. They differ in exactly one case:
`--heartbeat` on an unchanged host suppresses the component records, so
`counts.component` is `0` while `n_components` still states the real total. The
record then carries `"inventory_unchanged": true` and
`"inventory_components": 3993` so a receiver reconciles against the right one
instead of reporting a false discrepancy on every unchanged scan.

**The per-source counts add up.** The sum of `sources[*].components` equals
`n_components`. swinv checks this before writing and records a warning on the
report if it ever fails; the receiver should check it too. A component whose
source is not accounted for is a component whose disappearance nobody notices.

**Source names.** A source that produced components is named after the
cataloger that found it, with `-cataloger` trimmed: `javascript-package`,
`linux-kernel`, `windows-registry`. The four package databases swinv probes for
directly use short names - `dpkg`, `rpm`, `apk`, `portage` - and those are the
only ones that can report `error`, because they are the only ones whose absence
and unreadability can be told apart. `services` reports on the listening-socket
snapshot and always contributes zero components. `unattributed` counts
components that arrived with no `found_by`.

**A source that errors exits 5.** See the exit codes in
[FLAGS.md](FLAGS.md#exit-codes): a small valid inventory looks exactly like a
healthy scan of a minimal host, so the exit code is the only thing left to say
otherwise.


#### What the digest is built from

Identity alone: `type`, `name`, `version`, `root` and `purl` - the same tuple
deduplication uses. Deliberately **not** `locations`, `found_by`, `sha256`,
`licenses`, `cpes`, `vendor` or `change`: files get relinked, catalogers get
renamed upstream, `sha256` appears and disappears with `--hash`, and none of
that means a package was installed or removed. A digest that moved with them
would report change constantly and be ignored within a week.

#### When a full list is sent anyway

| Cause | Why |
|---|---|
| the digest differs | the point of the exercise |
| no previous scan is recorded for this host | nothing is known, so assume nothing |
| the state file is missing or unreadable | any doubt resolves toward sending too much |
| `--force-full` | an operator with reason to distrust the state |
| `--full-interval` has elapsed (default 24h; `0` disables) | a digest collision, a hand-edited state file or a bug must not hide a change indefinitely |

`--heartbeat` is the one thing that makes swinv remember something between
runs: a dotfile, `.swinv-heartbeat.json`, in the output directory, holding the
last digest per hostname. It is a dotfile so a collector globbing `*.json`
does not pick it up, and it lives beside the reports so deleting the output
directory deletes the state with it rather than leaving a stale digest to claim
a fresh machine is unchanged.

**Clock skew is yours to manage.** `scanned_at` comes from the host's clock. A
host running fast stamps its heartbeat in the future, and a consumer searching
a recent window may not see it at all.

```json
{"hostname":"web-01","os_id":"debian","os_version_id":"12","architecture":"amd64","scanned_at":"2026-08-19T11:35:35Z","name":"bash","version":"5.2.15-2+b7","type":"deb","purl":"pkg:deb/debian/bash@5.2.15-2%2Bb7?arch=amd64&distro=debian-12","cpes":["cpe:2.3:a:bash:bash:5.2.15-2\\+b7:*:*:*:*:*:*:*"],"locations":["/var/lib/dpkg/status"],"found_by":"dpkg-db-cataloger"}
```

Two differences from CSV worth knowing:

- **Multi-valued fields stay JSON arrays** rather than `;`-joined strings.
  Unlike CSV, the format can represent them losslessly.
- **The line carries the same fields as the CSV columns** - `hostname`, `machine_id`,
  `os_id`, `os_version_id`, `architecture`, `scanned_at`, `name`, `version`,
  `type`, `language`, `purl`, `cpes`, `licenses`, `locations`, `found_by`,
  `sha256` and `change` - the last two omitted when empty.

Empty optional fields are omitted from the object rather than emitted as `""`.

```sh
swinv --format ndjson --stdout | jq -c 'select(.type=="deb")'
```

---

## CycloneDX

`--format cyclonedx-json` writes a **CycloneDX 1.6** JSON document, extension
`.cdx.json`. This is the handoff to vulnerability scanners and other SBOM
consumers:

```sh
swinv --format cyclonedx-json --stdout > sbom.json
grype sbom:sbom.json
```

`swinv` itself does no vulnerability scanning; Anchore's `grype` is a separate,
downstream tool.

### It is built from our own model, not Syft's encoder

`internal/scan` is the only package permitted to import Syft. Using Syft's
CycloneDX encoder would drag Syft into `internal/output` and break that rule, so
the document is assembled from `model.Report` directly via
`github.com/CycloneDX/cyclonedx-go` (Apache-2.0). The practical consequence is
that the CycloneDX output is a projection of the same normalised, deduplicated,
sorted component list as every other format - not a second, independently
derived view of the machine.

### It is deterministic

**No `serialNumber` is generated.** This is a deliberate departure from the
CycloneDX convention of a per-document UUID: a random serial number would make
two consecutive inventories of an unchanged machine differ, which defeats the
whole point of keeping them. Likewise `bom-ref`s are derived from component
identity (the PURL when there is one, otherwise `type:name@version`, with a
`#2` suffix if two components would collide), and the only timestamp is
`scan.started_at`.

### The mapping

| CycloneDX | From |
|---|---|
| `metadata.timestamp` | `scan.started_at` |
| `metadata.tools.components` | `swinv` (with `swinv:tool:commit`) and `anchore/syft` at the version compiled in |
| `metadata.component` | The scanned machine, as a `device` with `bom-ref: swinv:host`; host facts become `swinv:host:*` properties, `os_pretty_name` becomes the description |
| `metadata.properties` | `swinv:schema_version` plus `swinv:scan:*` - `root`, `started_at`, `finished_at`, `duration_ms`, `ran_as_root`, `incomplete`, and one property per cataloger, exclusion, and warning |
| `components[]` | Each inventory component, as `type: "library"` |
| `components[].cpe` | The **first** CPE only - CycloneDX carries one per component. The rest are preserved as `swinv:component:cpe` properties. |
| `components[].licenses` | SPDX `id` for a single-token value, `name` for free text, `expression` for a lone compound expression containing `AND`/`OR`/`WITH` or parentheses |
| `components[].evidence.occurrences` | One entry per `location` |
| `components[].properties` | `swinv:component:type`, `:language`, `:found_by`, and any extra `:cpe` values |
| `services[]` | Each entry of the `services` block, with `bom-ref: swinv:service:<unit or executable basename>`, the schema's own `endpoints` field, and everything else as `swinv:service:*` properties - `confidence`, `executable`, `command`, `unit`, `container`, `user`, `pid`, `socket_activated`, and one `:evidence` property per line of the evidence trail |
| `services[].trustZone` | `host-network`, `host-loopback`, or `container-network`. Used rather than `x-trust-boundary`, which is a boolean about whether *using* a service crosses a boundary - a different claim that other tools read that way. |
| `services[].group` | The container name, for a service inside one. |
| `components[]` of type `operating-system` | The distribution, with `syft:distro:*` properties. This is where SBOM consumers look for it: Syft's decoder, which Grype uses for `grype sbom:`, reads the Linux release only from a component of this type. Without it every deb and rpm arrives with no distro and matching falls back to comparing backported versions against upstream numbering. |
| `dependencies[]` | One edge per service that was attributed, `dependsOn` the `bom-ref`s of the components behind it. This is the edge worth having: it answers "is anything internet-facing running the component this advisory is about" without a join |

Custom property names are namespaced with `swinv:` as CycloneDX asks. Note that
`type`, `language` and `found_by` survive only as properties - CycloneDX has no
native slot for them - so a generic SBOM consumer will see the PURL, version,
CPE and licences, and a `swinv`-aware one can recover the rest.

Nothing is dropped silently, but the document is **larger**: on the test fixture
it is 10,917 bytes against the JSON's 5,002, i.e. **roughly 2×**. That is the
cost of the property-list encoding, and it is why CycloneDX is not in the
default `--format`.

---

## Loading the CSV into a database

### Concatenating a fleet

The CSV is designed for exactly this: identical columns on every host, host
identity on every row, `\n` endings, no BOM. Keep one header and append the
rest:

```sh
# one header + every host's rows
head -1 web-01-latest.csv          >  all.csv
tail -q -n +2 *-latest.csv         >> all.csv
```

This works because the column shape does not vary with the flags each host ran
with - `sha256` and `change` are always present, empty or not.

### PostgreSQL

```sql
CREATE TABLE inventory (
    hostname      text,
    machine_id    text,
    os_id         text,
    os_version_id text,
    architecture  text,
    scanned_at    timestamptz,
    name          text,
    version       text,
    type          text,
    language      text,
    purl          text,
    cpes          text,
    licenses      text,
    locations     text,
    found_by      text,
    sha256        text,
    change        text,
    vendor        text
);
```

```sql
\copy inventory FROM 'all.csv' WITH (FORMAT csv, HEADER true);
```

`scanned_at` is RFC 3339 in UTC, which `timestamptz` parses without help.

Useful indexes:

```sql
CREATE INDEX ON inventory (purl);              -- the canonical join key
CREATE INDEX ON inventory (name, version);     -- "who runs X, and which X?"
CREATE INDEX ON inventory (hostname);          -- per-host drill-down
CREATE INDEX ON inventory (type);              -- narrow to one ecosystem
```

**Which hosts run a given package, and at which version?**

```sql
SELECT version, count(*) AS hosts, array_agg(hostname ORDER BY hostname) AS on_hosts
FROM inventory
WHERE name = 'openssl' AND type = 'deb'
GROUP BY version
ORDER BY version;
```

**Where has version drift crept in across the fleet?** Packages installed on
more than one host with more than one version in play - the list to hand to
whoever owns patching:

```sql
SELECT name, type,
       count(DISTINCT version)  AS versions,
       count(DISTINCT hostname) AS hosts,
       min(version) AS oldest,
       max(version) AS newest
FROM inventory
GROUP BY name, type
HAVING count(DISTINCT version) > 1 AND count(DISTINCT hostname) > 1
ORDER BY versions DESC, hosts DESC;
```

`min`/`max` here are lexicographic, not semantic - version strings are recorded
verbatim and are not parsed. Treat them as a hint, not an ordering.

**Which components carry a given licence?** `licenses` is `;`-joined, so match
on a delimited token rather than a bare substring, or `GPL-3.0-only` will also
match `LGPL-3.0-only`:

```sql
SELECT DISTINCT name, version, type, licenses
FROM inventory
WHERE ';' || licenses || ';' LIKE '%;GPL-3.0-only;%'
ORDER BY name;
```

To work with the multi-valued columns properly, expand them:

```sql
SELECT hostname, name, version, licence
FROM inventory, unnest(string_to_array(licenses, ';')) AS licence
WHERE licence LIKE 'GPL%';
```

### SQLite

```sh
sqlite3 inventory.db '.mode csv' '.import all.csv inventory'
```

When the target table does not yet exist, `.import` creates it from the header
row, so it comes out with the same 17 columns. Everything lands as `text`,
including `scanned_at` - RFC 3339 in UTC sorts and compares correctly as a
string, so that is rarely a problem.

### Working from the NDJSON instead

The NDJSON carries the same field names but keeps `cpes`, `licenses` and
`locations` as arrays, which is the better starting point if your target is a
JSON column or a document store. For anything that wants flat rows, use the CSV
- it is the format designed for it.

Loading it into a `jsonb` column needs one trick. `COPY` has no JSON mode, so
the delimiter and quote characters are set to control bytes that cannot appear
in JSON, which makes `COPY` treat each whole line as a single field:

```sql
CREATE TABLE feed (doc jsonb);
\copy feed FROM 'host-latest.ndjson' WITH (FORMAT csv, DELIMITER E'\x01', QUOTE E'\x02');
```

The arrays then stay queryable as arrays:

```sql
SELECT doc->>'name'            AS name,
       doc->>'type'            AS type,
       doc->'licenses'->>0     AS first_licence,
       jsonb_array_length(doc->'locations') AS location_count
FROM feed
ORDER BY name;
```

## Verification

Every recipe on this page has been executed against real output, not written
from memory:

| Step | Result |
|---|---|
| Concatenating two hosts' CSVs | 14,197 rows, one header, 0 malformed rows |
| PostgreSQL `\copy` (17 columns) | 14,197 rows, 2 hosts |
| SQLite `.import` | 14,197 rows, columns named from the header |
| NDJSON into `jsonb` | loads, arrays remain queryable |

The content that makes this non-trivial survived intact and identical in both
databases and in the source file: **2,596 rows contain a backslash** inside a
CPE (`cpe:2.3:a:acpid:acpid:1\:2.0.34-1ubuntu3:*:*:*:*:*:*:*`) and **11 rows
contain a comma inside the `licenses` field**. The backslash is the one to
watch: PostgreSQL's `COPY` treats it as an escape character in its *text*
format, so the `FORMAT csv` in the recipe above is load-bearing, not
decoration.
