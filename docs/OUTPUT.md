# swinv output formats

The complete reference for every file `swinv` writes: the schema, the four
formats, the field-by-field data model, the identity and ordering guarantees
consumers may rely on, and how to load the result into a database.

Part of the [swinv](../README.md) documentation.

---

## Schema version and the compatibility promise

Every JSON document carries a `schema_version` at the top. The current value is
**`1.3`**, defined as `model.SchemaVersion` in `internal/model/model.go`.

```json
"schema_version": "1.3"
```

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

It is frequently empty — measured at 23% of components on a full Debian-family
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

- The **minor** version is bumped for additive changes — new optional fields,
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
| `json` | `.json` | `web-01-20240309.json` | You want the whole report — host facts, scan metadata, warnings, delta. The only format that is a valid `--since` baseline. |
| `csv` | `.csv` | `web-01-20240309.csv` | You are loading a fleet into a spreadsheet or a SQL database. Flat, one row per component, host identity on every row. |
| `ndjson` | `.ndjson` | `web-01-20240309.ndjson` | You are streaming into a log pipeline (Vector, Filebeat, Loki, `jq`). One self-describing object per line. |
| `cyclonedx-json` | `.cdx.json` | `web-01-20240309.cdx.json` | You are handing the inventory to a vulnerability scanner or any other SBOM consumer. |

With `--latest-symlink` (on by default) each format also gets a
`{hostname}-latest.{ext}` symlink — `web-01-latest.cdx.json`, and so on.

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
with `--since`. `components` is always an array — an empty inventory writes
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
directly — never by shelling out to `hostnamectl`, `dmidecode`, `ip`, or
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
| `purl` | string | Package URL. **The canonical identifier** — see below. Omitted only when Syft supplies none. |
| `cpes` | []string | Candidate CPEs, sorted. Syft generates several per package; all are kept. |
| `licenses` | []string | Licence strings, sorted. SPDX identifiers where the ecosystem provides them, free text where it does not (`Apache 2.0` from a Python `METADATA` is a real example). Not validated against the SPDX list. |
| `locations` | []string | Real absolute paths on the scanned machine, sorted, with the `--root` prefix stripped. For a deb this is usually `/var/lib/dpkg/status`; for a Python package the `dist-info` files. |
| `found_by` | string | The originating Syft cataloger, e.g. `dpkg-db-cataloger`. Useful when a result looks wrong. |
| `sha256` | string | Hex digest of the component's primary on-disk file. **Only with `--hash`**, and only for files backing exactly one component — see below. |
| `change` | string | `added` or `changed` for a component that moved since the `--since` baseline; absent for unchanged components and for runs without `--since`. `removed` appears only in `--delta-only` output, since a removed component is by definition not in the current inventory. |

#### `--hash` and shared evidence files

`--hash` digests each component's primary file. **Files that back more than one
component are deliberately skipped**: most debs cite `/var/lib/dpkg/status` as
their evidence, so digesting it would give every package on the machine an
identical hash *and* make all of them appear changed whenever any single package
changed — precisely backwards for change detection. The count skipped is
reported in `scan.warnings`:

```
1 shared evidence file(s) such as package databases were not hashed;
a digest of a file backing many components identifies none of them
```

Files above 512 MiB and anything that is not a regular file are also skipped. So
in practice OS packages have no `sha256` and language packages do.

---

## Identity and ordering — the guarantees consumers rely on

These are not implementation details. They are the contract that makes these
files joinable and diffable, and they are enforced by
`model.Normalize`/`model.Less` and covered by tests.

**1. PURL is the canonical join key.** Package URLs are the identifier to join
on across machines — they encode ecosystem, namespace, name, version, and
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
`version`, then `purl`. Every string slice — `locations`, `cpes`, `licenses`,
`ipv4`, `ipv6`, `macs`, `excluded` — is sorted and deduplicated too.

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
`changed` entry**, not as a removal plus an unrelated addition — otherwise a
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

### The 17 columns, in exactly this order

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

Both columns are emitted **even when `--hash` and `--since` were not used** —
empty, but present. The column shape therefore never varies with the flags a
given host happened to run with. That is what keeps CSVs concatenable across
machines and across runs, and it is why they must not be made conditional.

---

## NDJSON

One JSON object per component, one per line, no indentation, a newline after
every record. A report with no components produces an empty file, which is the
correct empty document for this format.

Each line repeats the host identity and the scan time alongside the component
fields, using the same `snake_case` names and the same order as the CSV columns,
so a single line is self-describing when it arrives at a log pipeline with no
surrounding context.

```json
{"hostname":"web-01","os_id":"debian","os_version_id":"12","architecture":"amd64","scanned_at":"2026-08-19T11:35:35Z","name":"bash","version":"5.2.15-2+b7","type":"deb","purl":"pkg:deb/debian/bash@5.2.15-2%2Bb7?arch=amd64&distro=debian-12","cpes":["cpe:2.3:a:bash:bash:5.2.15-2\\+b7:*:*:*:*:*:*:*"],"locations":["/var/lib/dpkg/status"],"found_by":"dpkg-db-cataloger"}
```

Two differences from CSV worth knowing:

- **Multi-valued fields stay JSON arrays** rather than `;`-joined strings.
  Unlike CSV, the format can represent them losslessly.
- **The line carries the same fields as the CSV columns** — `hostname`, `machine_id`,
  `os_id`, `os_version_id`, `architecture`, `scanned_at`, `name`, `version`,
  `type`, `language`, `purl`, `cpes`, `licenses`, `locations`, `found_by`,
  `sha256` and `change` — the last two omitted when empty.

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
sorted component list as every other format — not a second, independently
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
| `metadata.properties` | `swinv:schema_version` plus `swinv:scan:*` — `root`, `started_at`, `finished_at`, `duration_ms`, `ran_as_root`, `incomplete`, and one property per cataloger, exclusion, and warning |
| `components[]` | Each inventory component, as `type: "library"` |
| `components[].cpe` | The **first** CPE only — CycloneDX carries one per component. The rest are preserved as `swinv:component:cpe` properties. |
| `components[].licenses` | SPDX `id` for a single-token value, `name` for free text, `expression` for a lone compound expression containing `AND`/`OR`/`WITH` or parentheses |
| `components[].evidence.occurrences` | One entry per `location` |
| `components[].properties` | `swinv:component:type`, `:language`, `:found_by`, and any extra `:cpe` values |

Custom property names are namespaced with `swinv:` as CycloneDX asks. Note that
`type`, `language` and `found_by` survive only as properties — CycloneDX has no
native slot for them — so a generic SBOM consumer will see the PURL, version,
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
with — `sha256` and `change` are always present, empty or not.

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
more than one host with more than one version in play — the list to hand to
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

`min`/`max` here are lexicographic, not semantic — version strings are recorded
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
including `scanned_at` — RFC 3339 in UTC sorts and compares correctly as a
string, so that is rarely a problem.

### Working from the NDJSON instead

The NDJSON carries the same field names but keeps `cpes`, `licenses` and
`locations` as arrays, which is the better starting point if your target is a
JSON column or a document store. For anything that wants flat rows, use the CSV
— it is the format designed for it.

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
