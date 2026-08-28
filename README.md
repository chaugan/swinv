<p align="center">
  <img src="docs/assets/logo.png" width="132"
       alt="An open port wired inward through three nested boundaries: host, container, package">
</p>

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
software it can find - OS packages on Linux, the registry on Windows, language
packages on both, loose binaries that no package manager ever installed, and
the contents of the containers it is running or has stopped - then writes the
result to local JSON and CSV files.

It also records **what is actually listening and what is exposed at the
network edge**, on Linux and Windows both, and follows a published port into
the container that answers it - so an open port on the host resolves to the
exact package inside the container serving it:

```
0.0.0.0:80  →  docker-proxy  →  container 9d5a98d0dc04  →  /usr/sbin/nginx
            →  pkg:apk/alpine/nginx@1.27.5-r1  (Alpine 3.21.3, on an Ubuntu host)
            →  linking libcrypto.so.3 from pkg:apk/alpine/libcrypto3@3.3.3-r0
```

That is the question an inventory of packages cannot answer on its own, and
the reason this exists - see [why not just use…?](#why-not-just-use)

`swinv` **is** no server, no daemon and no database - it is one binary that
runs, writes files and exits - and **no inventory data ever leaves the
machine**. Collecting the files afterwards is deliberately your job: `rsync`,
Ansible, a log shipper, or `scp`.

It *talks to* exactly one daemon, and only when containers are present: the
local container runtime, over its Unix socket or named pipe. That is the only
way to see inside a stopped container, and the only way to see inside any
container from Windows, where a Docker Desktop container is a Linux process in
a virtual machine that no Windows API reaches. It is local kernel IPC with no
address and no route, it reads the container list and files and nothing else -
no create, no exec, no attach - and `--no-containers` turns it off.

By default the one piece of network activity is an optional reverse-DNS lookup
used to fill in the host's FQDN - ordinary name resolution against your
configured resolver, carrying no inventory data. `--offline` turns it off, at
which point the run performs no network activity at all. `--transmit` opts in
to uploading the scan to one HTTPS endpoint; it is off unless you ask for it,
and it never replaces the files on disk.

Detection comes from [Syft](https://github.com/anchore/syft), imported as a
library, which gives roughly 40 package ecosystems and a binary classifier
in-process with no subprocess overhead.

## Contents

**Start here** &nbsp; [What it reads](#what-it-reads) · [Quickstart](#quickstart) · [Install](#install)

**Using it** &nbsp; [Everyday flags](#everyday-flags) · [Output file naming](#output-file-naming) · [What is skipped by default](#what-is-skipped-by-default) · [Change detection](#change-detection) · [Vulnerability scanning](#vulnerability-scanning)

**Platforms** &nbsp; [Windows](#windows) · [Platform testing status](#platform-testing-status)

**Running it** &nbsp; [How often to run](#how-often-to-run-and-what-it-costs) · [Security and privacy](#security-and-privacy) · [Performance](#performance) · [Known limitations](#known-limitations)

**The project** &nbsp; [Why not just use…?](#why-not-just-use) · [Architecture](#architecture) · [Building](#building) · [Licensing](#licensing) · [Documentation](#documentation) · [Non-goals](#non-goals)

## What it reads

Every box is a source `swinv` reads directly. Nothing is inferred, nothing is
fetched over a network, and nothing is left running afterwards.

```
┌─────────────────────────────────────┬─────────────────────────────────────┐
│ LINUX HOST                          │ WINDOWS HOST                        │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ dpkg · rpm · apk · pacman · alpm    │ uninstall registry   HKLM · HKU     │
│ ~40 language ecosystems             │ Store and MSIX packages             │
│   python npm go java gem cargo      │ component store  servicing state    │
│ loose ELF binaries                  │ NTFS master file table              │
│ package file lists  owns an exe     │   --full-scan, opens no file        │
│ /proc/net/{tcp,tcp6,udp,udp6}       │ PE VERSIONINFO + py/npm manifests   │
│ /proc/<pid>/{fd,exe,cgroup,status}  │ iphlpapi  sockets with owning pid   │
│ /proc/<pid>/ns/{net,mnt}            │ QueryFullProcessImageName           │
│ /proc/self/mountinfo                │                                     │
│ ELF DT_NEEDED · dynamic symbols     │ PE import tables of listeners       │
│ cron · systemd units · SUID bits    │ scheduled tasks  XML, no COM        │
│                                     │ Run keys · Startup folder           │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ CONTAINERS   running + stopped      │ MACHINE IDENTITY                    │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ /proc/<pid>/root  its filesystem    │ machine-id · hostname · boot-id     │
│ its own dpkg / apk / rpm database   │ kernel · os-release · DMI serial    │
│ its own os-release  another OS      │ IPs · MACs · virtualisation         │
│ runtime API  image · digest · ports │ Windows: CurrentVersion registry    │
│ OCI bundle  pod name · namespace    │   MachineGuid · build · UBR         │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ BLIND SPOTS                         │ checked, then declared              │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ /etc/docker/daemon.json             │ /var/lib/kubelet  is this a node    │
│   is userland-proxy disabled        │   NodePort has no socket to find    │
└─────────────────────────────────────┴─────────────────────────────────────┘
                                      │
                                      ▼
                    ┌───────────────────────────────────┐
                    │  swinv                            │
                    │  one binary · no daemon · offline │
                    └───────────────────────────────────┘
                                      │
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ components[]   every package, with PURL and CPE                           │
│ services[]     what is listening, and what installed it                   │
│ exposure[]     one row per open port on this host                         │
│ containers[]   each container, its OS and its software                    │
│ links          what each binary loads, joined to owning packages          │
│ config[]       cron, timers, services, SUID, autoruns, with ATT&CK ids    │
│ scan           what was skipped, and what could not be seen               │
├───────────────────────────────────────────────────────────────────────────┤
│ written as     JSON · CSV · NDJSON · CycloneDX                            │
│                + services and exposure CSV sidecars                       │
│ streamed as    heartbeat · exposure · container · link records            │
│                for a log forwarder, on request                            │
└───────────────────────────────────────────────────────────────────────────┘
```

The kinds of source answer different questions and none knows the others. A
package database is authoritative about what it installed; a listening socket
is authoritative about what is bound right now; a crontab or a unit file is
authoritative about what the machine will run next, whether or not anything
installed it. Joining them is the work, and it is what the rest of this
document is about.

The bottom row is the one most inventory tools leave out. A port published by
a netfilter rule has no socket to find, so a host running Kubernetes NodePort
or Docker with `userland-proxy` disabled would otherwise produce a report
identical to one with nothing exposed at all. `swinv` checks for both and says
so in `scan.exposure_blind_spots`, because "looked and found nothing" and
"could not look" are different answers.

---

## Quickstart

```sh
sudo dpkg -i swinv_0.9.5-1_amd64.deb   # or: sudo rpm -i swinv-0.9.5-1.x86_64.rpm
swinv --out /tmp/inv                   # scan /, write JSON + CSV
```

No package? The binary is static and has no dependencies, so
`install -m0755 swinv-v0.9.5-linux-amd64 /usr/bin/swinv` is equally fine, as is
`make build` from a clone.

That writes timestamped files plus `-latest` symlinks - and, run as root with
containers present, two more alongside them for the services and the network
edge:

```console
/tmp/inv/web-01-20260822T131806.571Z.json
/tmp/inv/web-01-20260822T131806.571Z.csv
/tmp/inv/web-01-20260822T131806.571Z-services.csv     # root, Linux or Windows
/tmp/inv/web-01-20260822T131806.571Z-exposure.csv     # one row per open port
/tmp/inv/web-01-latest.json -> web-01-20260822T131806.571Z.json
/tmp/inv/web-01-latest.csv  -> web-01-20260822T131806.571Z.csv
```

Look at what came out, pipe a single format, or ask what changed since last time:

```sh
jq '.components | length' /tmp/inv/web-01-latest.json
swinv --format json --stdout | jq '.components[0]'
swinv --since /var/lib/swinv/*-latest.json      # added/removed/changed
```

To run it daily across a fleet, install the `.deb` or `.rpm` and enable the
timer - see [Install](#install).

Running as root finds more (root-only paths, DMI serials). Running unprivileged
is fully supported, never an error, and records a warning saying what it missed.

### What comes out

Everything below is real output, reproducible from a clone - the repository ships
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
  "schema_version": "1.14",
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
    "scan_id": "9f2c4b1a-7e83-4c1d-b2a6-0d5e8f3a1c72",
    "sources": [{"source": "packages", "records": "components", "status": "ok", "count": 7}],
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

- **`vendor`** - who made it, taken from whatever the ecosystem records: an rpm
  `Vendor`, a dpkg `Maintainer`, a Python or npm `Author`, a Windows PE
  `CompanyName`.
- **`root`** - which filesystem root it was found in. `/` is the machine
  itself; anything else is a snap base, a container layer or a mounted image,
  which are separate operating systems with their own release and patch state.
- **`owned_by`** - the OS package that installed it, where one did. Ubuntu's
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

A real host produces the same shape at a very different scale - around 14,000
components on the machine this was developed on.

#### What is listening

Run as root on Linux, the report also carries a `services` block: every
listening socket, the process behind it, its systemd unit or container, and
which installed software owns its executable.

```console
$ sudo swinv --out /var/lib/swinv
swinv: containers: 609 package(s) from inside containers added to the inventory
swinv: services: 29 attributed to installed software, 9 running software nothing installed, 1 unidentified
swinv: exposure: 15 of 46 endpoint(s) bound beyond loopback, 11 of those identified; 17 container(s) with 32 listening service(s)
swinv: wrote /var/lib/swinv/web-01-20260822T131806.571Z.json
swinv: wrote /var/lib/swinv/web-01-20260822T131806.571Z.csv
swinv: wrote /var/lib/swinv/web-01-20260822T131806.571Z-services.csv
swinv: wrote /var/lib/swinv/web-01-20260822T131806.571Z-exposure.csv
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
no package manager installed - a vendor binary under `/opt`, and two copies of
`/usr/local/bin/node`. Nothing in a package list says so.

`confidence` is recorded rather than implied, and every finding carries the
`evidence` it rests on, because a bare claim that "port 443 is nginx 1.24" is
indistinguishable from a guess by the time it reaches anyone. Socket-activated
ports are marked as such rather than blamed on `systemd`, since the daemon may
not be running at all. Unprivileged, the ports are still reported and the
processes behind them mostly are not - which is stated, not hidden.

It all comes from `/proc`: no `ss`, no `netstat`, no `lsof`, no D-Bus.
`--no-services` skips it; `--no-service-command` keeps it but drops the command
lines, which is where secrets end up.

#### What is exposed, and what is inside the containers

The same run records the network edge: one row per listening socket in the
**host** network namespace, with the software behind it - following a published
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

That PURL is the point. It comes from the **container's own package database**
- an Alpine container on an Ubuntu host - and it is a coordinate Grype and
Trivy match today. An image reference is not: there is no `oci` matcher
anywhere in the chain, so an image PURL alone yields a component that gets
reported clean because nothing ever looked at it. swinv emits the image digest
as a *locator*, on its own field, never as an identity.

`containers[]` lists every container and what it runs, with its own OS -
`rhel-8.10`, `alpine-3.21.3`, `wolfi-20230201`, each a different operating
system from the host, deciding which advisories apply. On the machine this was
developed on that is 17 containers across five distributions and **1,281
packages**, 570 of them inside containers that are not even running.

Here is that same nginx from the other end - the container itself, with what
it runs and where the host publishes it:

```jsonc
{
  "id": "9d5a98d0dc04…", "name": "notprem", "runtime": "docker",
  "state": "running",
  "declared_endpoints": ["8080/tcp"],
  "image": {
    "ref": "nginxinc/nginx-unprivileged:1.27-alpine",
    "manifest_digest": "sha256:28d91bdce70ad09025ea901458fdd149259d8e05982ade79d4ef2c0d9470eb48"
  },
  "os_id": "alpine", "os_version_id": "3.21.3",
  "services": [{
    "endpoints": ["0.0.0.0:8080/tcp"],
    "executable": "/usr/sbin/nginx",
    "processes": 9,
    "components": ["pkg:apk/alpine/nginx@1.27.5-r1?arch=x86_64&distro=alpine-3.21.3"],
    "confidence": "high",
    "published_as": ["0.0.0.0:80/tcp", "[::]:80/tcp6"],
    "evidence": [
      "listening inside the container's own network namespace, which is reachable from this host only if something publishes it",
      "the container's own os-release says alpine 3.21.3",
      "the container's package database records pkg:apk/alpine/nginx@1.27.5-r1… as owning this file"
    ]
  }]
}
```

`processes: 9` is nginx's master and its eight workers folded back into one
service - they share the socket, and reporting nine would misstate both what is
running and how much of it. `published_as` is the back-link to the `exposure`
row above.

**Stopped containers are included too.** They serve nothing, so they get no
exposure row - but a stopped `postgres:14` still holds 142 packages with the
same advisories, and it will be up again:

```jsonc
{
  "id": "5c9bf9afa5d7…", "name": "argilla-postgres-1",
  "state": "exited",
  "declared_endpoints": ["5432/tcp"],
  "image": {"ref": "postgres:14", "manifest_digest": "sha256:aff5787306…"},
  "os_id": "debian", "os_version_id": "13",
  "services": [{
    "endpoints": ["5432/tcp"],
    "command": "docker-entrypoint.sh postgres",
    "confidence": "medium",
    "evidence": [
      "reported by the container runtime, state exited",
      "these endpoints are declared by the image or the run configuration, not observed",
      "142 package(s) read from the container's own database"
    ]
  }]
}
```

`declared_endpoints` is what `EXPOSE` or `-p` says it would serve on - **a
declaration, never an observation**, which is why a stopped container's ports
appear here and never in `exposure`. A container with no network endpoint at
all is skipped, since it is not part of this machine's attack surface.

There are two routes in, with different precision, and the report says which
was used:

| Route | Gives | Where |
|---|---|---|
| `/proc/<pid>/root` | the package owning a **specific listening executable** | Linux, running containers |
| the runtime's archive endpoint | the container's **whole package list** | stopped containers, and everything on Windows |

The first wins where it can be asked: naming the package behind a listener
beats listing the two hundred packages that share its filesystem. Components
carry `attributes.scan_scope` saying which produced them.

**`bind_scope` is about the bind, not about reachability.** swinv reads no
firewall, no NAT table and no security group, so there is no "public" and
nothing says "internet-facing". And because a port published by a netfilter
rule has no listening socket at all - Kubernetes NodePort, Docker with
`userland-proxy` disabled, Podman's default netavark - every report carries
`scan.exposure_blind_spots` naming what it could not see. **A short exposure
list means nothing until you have read that array.**

**[Why this exists and how it is built →](docs/SERVER-ROLES.md)**

#### Shipping it to a fleet

The NDJSON stream is the one shape built for a log forwarder, and two flags
make it usable at fleet scale.

```sh
swinv --out /var/lib/swinv --format ndjson --heartbeat --ndjson-include all
```

**`--heartbeat`** puts a one-line digest of the inventory at the head of the
stream and omits the component records when that digest matches the last scan.
Every scan otherwise restates the whole inventory - correct, since a package
that disappears is genuinely gone rather than merely unmentioned, and expensive:
5,000 hosts averaging 14,000 components scanned hourly is over a billion records
a day, nearly all identical to the day before. Measured on a 23,493-component
host: **23,494 lines became 1**, while the JSON stayed complete at 24 MB.

It is never a delta. When anything changes the whole list is sent again, because
a delta cannot express a removal - and "this package is no longer installed" is
the fact that decides whether a vulnerability is fixed or merely unreported.

**`--ndjson-include`** adds `exposure`, `container`, `link` and `config`
records, so what is listening - what it loads, and what the machine is
configured to run - reaches the stream and not only the JSON document. Exposure and container records are small - 46 and 16 against 2,715
components on a 17-container host - so they are sent even on an unchanged
heartbeat scan: a port opening is exactly the kind of change that happens while
installed software does not. Link records follow the components instead: they
are derived from the installed software, and an unchanged heartbeat scan
suppresses both together.

Every extra record carries a `record_type` an older consumer can skip, and a
line without one is a component, so nothing that reads the stream today breaks.

**[Record shapes and the streaming gotchas →](docs/OUTPUT.md#the-heartbeat)**

#### What each binary actually loads

Every ELF binary already carries a database of its own dependencies - the
`DT_NEEDED` entries name the shared libraries it loads, and the dynamic symbol
table names every function it imports, with versions. swinv reads both without
executing anything and joins each library to the package that owns it:

```jsonc
{ "executable": "/usr/sbin/sshd",
  "links": [
    {"soname": "libcrypto.so.3",
     "path": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
     "purl": "pkg:deb/ubuntu/libssl3t64@3.5.5-1ubuntu3.3?upstream=openssl",
     "n_symbols": 120},
    {"soname": "libz.so.1", "purl": "pkg:deb/ubuntu/zlib1g@1.3.1", "transitive": true}
  ] }
```

This is what turns "a CVE landed in openssl" from *flag every machine that has
it on disk* into *rank the hosts where a network-facing service actually loads
it* - and `--elf-symbols` adds the imported function lists
(`RSA_set0_key@OPENSSL_3.0.0`) as supporting evidence. Resolution follows
`ld.so` without running it, chases ldconfig's symlinks to the file a package
actually ships, and stays jailed inside a container's own filesystem, so nginx
in an Alpine container links Alpine's `libcrypto3`, never the host's openssl.
Measured on this machine: 144 of 144 libraries across every listening service
resolved to an owning package.

Three limits, stated in the data rather than discovered: `dlopen`'d modules
(nginx modules, Python extensions, PAM, NSS) are invisible to `DT_NEEDED` and
the evidence says so; a symbol list names the API entry points called, not the
code that runs - most CVEs live in internal functions that appear in no import
table, so "loads the library" is the reliable signal; and a library with a
path but no `purl` is one nothing installed owns, which for a CVE consumer is
the more interesting case.

`--elf-scope all` extends the probe from the listening executables to every
ELF under the standard binary directories - 5,845 binaries in about a minute
on the machine this was developed on.

The same question gets answered on Windows: a binary's **PE import table**
names the DLLs it loads and the functions it imports, resolved the way the
loader searches (application directory first - the order that makes DLL
planting a technique - then System32), and joined to the products the
inventory identified. System DLLs carry `os_component` instead of an owner,
so `KERNEL32.dll` does not masquerade as the interesting unowned case.
`--elf-scope all` with `--full-scan` extends the probe from the listeners to
**every executable file the MFT enumeration saw** - the enumeration is
already the index of the machine's binaries, so no second walk is paid for -
and at that scope OS links are not recorded at all: the OS is represented by
its updates, and five million rows of "loads KERNEL32" answer no question a
consumer asks. LoadLibrary and delay-loaded imports are the Windows
`dlopen`: invisible, and the evidence says so.

What the first real all-scope run of this found, on one ordinary laptop:
**three generations of OpenSSL loaded side by side** - 3.4.0, 3.0.16 and the
end-of-life 1.1.1g - plus private copies vendored inside an MQTT broker and
two Siemens OT tools, and 9,986 links against a 2011-era Qt 4.8.0. The
leaderboard falls out of one query:

```sh
jq -r 'select(.record_type == "link") | select(.purl != null) | .purl' scan.ndjson \
  | sort | uniq -c | sort -rn | head
```

and "who loads the EOL OpenSSL" is the same query with
`select(.purl | test("1.1.1"))` - each row carrying the executable that
loads it.

#### What the machine is configured to run

Installed software and listening sockets still miss a third class of fact:
the persistence and privilege mechanisms MITRE ATT&CK is largely made of.
Those are configurations, not software defects - no CVE feed will ever list
them - so `swinv` collects them the same way it collects everything else,
as local reads. On Linux: cron jobs, systemd timers and services, SUID/SGID
binaries, sudo rules, SSH authorized keys, accounts, kernel modules,
`ld.so.preload` and shell init. On Windows: Scheduled Tasks, Run-key autoruns, the services
registry, Defender exclusions, Image File Execution Options and AppInit_DLLs.
Each entry names the executable it runs, joined to the package that installed
it, and the ATT&CK technique the mechanism is the surface for:

```jsonc
{ "record_type": "config", "kind": "cron",
  "path": "/etc/cron.d/e2scrub_all", "user": "root", "schedule": "10 3 * * *",
  "executable": "/sbin/e2scrub_all",
  "purl": "pkg:deb/ubuntu/e2fsprogs@1.47.2-3ubuntu2", "attack": "T1053.003" }
```

Collecting an entry is not a finding, and the record claims nothing beyond
the surface - "this technique has a surface here" is a different sentence
from "you are compromised", and the data keeps them apart. The findings are
joins a consumer makes: a **root cron job whose script is `world_writable`**,
a **SUID binary with no `purl`**, a **unit whose `ExecStart` points outside
every package-owned path**. The first real run of this feature found two of
those on the machine it was developed on.

osquery and Wazuh collect several of these tables too, as resident agents
with a server behind them; what `swinv` adds is the same one-shot, offline,
no-daemon shape as the rest of the report, with the package join and the
technique id already on every row. `--config-scope all` extends the SUID
walk to the whole filesystem; `--no-service-command` drops the command lines
here for the same reason it exists at all, keeping the joinable executable
paths.

**[Full schema, NDJSON, CycloneDX and SQL loading →](docs/OUTPUT.md)**

Two runs on an unchanged machine produce **byte-identical output** apart from the
timestamps in `scan` - which is what makes these files worth diffing.

## Install

Every tagged release publishes static binaries and `.deb`/`.rpm` packages for
`linux/amd64` and `linux/arm64`, a `windows/amd64` binary, and a `SHA256SUMS`
file to check them all against. Pick whichever fits how you manage machines.

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

### Any Linux - the static binary

It has no dependencies of any kind, not even libc, so this works everywhere
including Alpine and distroless images:

```sh
curl -LO https://github.com/chaugan/swinv/releases/latest/download/swinv-linux-amd64
curl -LO https://github.com/chaugan/swinv/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
sudo install -m0755 swinv-linux-amd64 /usr/bin/swinv
```

Use `swinv-linux-arm64` for 64-bit ARM. Every release publishes each binary
twice - once with the version in the name for archival, and once without, so
these `latest/download` URLs keep working and never need editing. **Always check the digest** - you are about
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
`etc/os-release`, and applies the usual layout exclusions to it - otherwise
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
`/var/lib/swinv`. **The daily timer ships deliberately disabled** - turning on a
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
| Alpine | apk | **16 / 16** - and the static binary runs on musl |
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
| CycloneDX → `grype` | **Tested** - 234 matches from a 568-component document |
| `linux/arm64` | **Tested** under emulation - apk 16/16, dpkg 78/78, rpm 147/147, `architecture` correctly `arm64` |
| Listening sockets and exposure | **Tested** on Linux and on Windows, in CI and on real hosts |
| Containers, running and stopped | **Tested** on a host with 17 containers across 5 distributions; CI starts its own and asserts the published port resolves to the package inside |

All of this runs in CI on every push, so a Syft upgrade that quietly stops
reading one package database shows up as a count mismatch rather than as a
thinner inventory noticed months later.

Two caveats, honest rather than alarming.

arm64 is verified under QEMU emulation, not on physical ARM hardware.
Emulation exercises the code but not the machine, so if you run this on a
Raspberry Pi or an ARM instance, that is still worth reporting.

**Kubernetes has not been run against a real node.** `hostNetwork` pods are
ordinary host listeners and work; `NodePort` is a netfilter rule with no
listening socket and is invisible by construction, which every report declares
in `scan.exposure_blind_spots`. What is untested is the pod and namespace
identity, which is read from CRI annotations whose on-disk paths differ between
containerd and CRI-O. If you run this on a node, that is the result I most want
to see.

### Windows

| Surface | Status |
|---|---|
| uninstall registry | **Tested** on Windows 11 25H2 and Server 2025 - 380 and 423 products |
| Store and MSIX packages | **Tested** - 135 packages on a real laptop |
| Windows servicing state | **Tested** - cumulative update version asserted equal to the host's build and UBR |
| MFT enumeration | **Tested** - 2,889,563 records in 12 s, every path resolved |
| PE version extraction | **Tested** - 14,769 components from 19,550 files |
| Python and npm manifests | **Tested** - 2,266 packages from 2,598 manifests |
| Host identity | **Tested** - `os_id`, `machine_id`, build and UBR, on client and server |

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
| component store | Windows servicing state - cumulative update, servicing stack, .NET rollup |
| `iphlpapi` | what is listening, with the process holding each socket |
| PE import tables | what each binary loads, joined to installed products (`--elf-scope`) |
| task store and Run keys | scheduled tasks and autoruns, with ATT&CK ids (`--config-scope`) |
| the container runtime | containers, their images and their packages |

The same run produces `services[]`, `exposure[]` and `containers[]` - see
[what is exposed](#what-is-exposed-and-what-is-inside-the-containers). Two
things work differently here than on Linux, and the report says so rather than
leaving you to infer it:

- **Most of what listens on Windows is the operating system.** On one real
  laptop, 77 of 173 non-loopback endpoints were `svchost.exe` and the kernel.
  They carry `os_component: true` - **filter that out before treating
  `medium` as "unmanaged software"**, or every host contributes several dozen
  false entries.
- **A container's software comes from the runtime, not the filesystem.** A
  Docker Desktop container is a Linux process inside a WSL2 virtual machine
  that no Windows API reaches, so swinv asks the engine over its named pipe.
  That covers running and stopped containers alike.

Attribution on Windows leans on `--full-scan`: the uninstall registry records
an install *directory* and never the executables under it, and 72% of entries
record no directory at all. With `--full-scan` a listening executable matches a
catalogued PE file exactly. On that same laptop it took identified endpoints
from 49 to 58, and from zero `high` confidence to 21.

### `--full-scan`

Adds everything the registry does not record - software unpacked into a
directory, vendor tools, anything copied onto the machine - plus Python and npm
packages. It needs an elevated process and an NTFS volume.

It does **not** walk directories. It enumerates the Master File Table: 2.9
million records in five seconds on a real laptop, opening nothing. Then it
discards what the registry already accounts for and what belongs to Windows
itself, and opens only the remainder - **19,549 files of 99,920** on that
machine, an 80% reduction in the one operation that costs anything.

| | |
|---|---|
| MFT enumeration | 2,889,563 records in 12 s, no file opened |
| attributed to a registry product | 26,827 - version already known, not opened |
| operating-system and Store territory | 53,553 - accounted for elsewhere |
| **opened to extract a version** | **19,550** |

The first `--full-scan` on a machine is slow and the rest are not. Antivirus
scans each executable the first time it is opened and caches the result, so the
same command took **14 minutes** cold and **1 second** warm - a scheduled task
pays that once.

`--volumes D:` or `--volumes D:,E:` selects which volumes to enumerate, and
**replaces** the default of `C:` rather than adding to it.

### Language ecosystems

Python and npm packages are found during the same MFT pass, by their manifests -
`*.dist-info/METADATA`, `*.egg-info/PKG-INFO`, `package.json` - and only those
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

A Windows report also carries the **patch-level join key** - `os_build`
(`10.0.26200.9168`), `os_display_version` (`25H2`), `os_edition` and
`os_installation_type` - on the host record and on the heartbeat line. That
is what makes an offline patch-currency check arithmetic instead of a guess:
Microsoft's Security Update Guide keys every remediation on the OS build, the
host states which build it is on, and the comparison needs no inference from a
display name. The release distinguishes 24H2 from 25H2 for end-of-service (an
enablement package keeps the older servicing branch, so the cumulative
update's version alone cannot), and the edition separates a client from a
server that share a build branch but sit ~24,000 update revisions apart.

Two Windows quirks are handled: the registry still reads `Windows 10 Pro` on
Windows 11 hosts, and client and server share build numbers - Windows 11 24H2
and Server 2025 are both `26100` - so a server reports its release year rather
than a client major.

### What is out of scope

Operating-system components are **not** inventoried file by file. `C:\Windows\
WinSxS` held 39,536 executables on a real machine - 40% of every candidate on
the volume - and they are hard-linked servicing copies that say little
individually. The installed servicing packages express the same thing in the
form an operator patches by, with the cumulative update's version equal to the
host's build and UBR.

Store apps and per-user applications are registered per user, so a scan running
as a service account sees that account's and no other's.

**[Design, measurements and open questions →](docs/WINDOWS.md)**

## Why not just use…?

Most of what `swinv` does, something else also does. One thing it does I have
not found in another tool, and it is the reason this exists - see
[the chain](#the-chain-nobody-else-seems-to-walk) below.

| | What it gives you | Why `swinv` |
|---|---|---|
| **`syft` CLI** | The same detection engine - `swinv` imports it | Adds host identity, stable dated/rotating filenames, atomic writes, day-over-day deltas, and a flat CSV built for SQL. Syft has no concept of a listening socket. One binary, no JSON round-trip |
| **osquery** | Far broader host telemetry, SQL over live state | `swinv` is a oneshot binary, not an always-on agent with a daemon and its own query language. osquery can join `listening_ports` to `processes`, but it has no table saying which *package* owns a process's executable, and no package table for the inside of a container |
| **`dpkg -l` / `rpm -qa`** | Fast, already installed | OS packages only. Misses every language ecosystem and every unmanaged binary, and the output differs per distro |
| **`grype dir:/`** | Package discovery *and* CVE matching in one pass - also Anchore's, also Syft-powered | A complement, not a competitor. `grype` needs a vulnerability database it downloads and refreshes; `swinv` runs `--offline` with no network at all. `grype` produces findings, `swinv` produces an inventory. Keep the SBOM and you can re-match new CVEs daily **without re-walking the filesystem** - see [below](#vulnerability-scanning) |
| **`trivy` / image scanners** | Deep, authoritative container image analysis, and CVE matching | Image-centric: you point them at an image. They do not tell you *which* image is running on *this* host, on *which* port, or that a stopped container still holds a vulnerable one. `swinv` answers that and hands you the digest to scan |
| **Wazuh / agent inventory** | Fleet inventory with a server, dashboards, alerting | A server, an agent and a database. `swinv` writes files and exits; collecting them is your job. If you want the dashboards, use Wazuh |

### The chain nobody else seems to walk

Every tool above can tell you *some* of this. What I have not found elsewhere
is a tool that walks the whole way, on one host, in one pass, offline:

```
0.0.0.0:80 on this host
  → held by docker-proxy, whose own package is not the answer
  → forwards to container 9d5a98d0dc04
  → /usr/sbin/nginx inside it
  → pkg:apk/alpine/nginx@1.27.5-r1  (Alpine 3.21.3, on an Ubuntu host)
  → which links libcrypto.so.3 from pkg:apk/alpine/libcrypto3@3.3.3-r0
```

Those last lines are coordinates Grype and Trivy match today. Getting to them
means crossing four boundaries most tools stop at: **socket to process**,
**host to container**, **executable to the package that installed it**, and
**binary to the shared libraries it actually loads**. Package scanners do the
third and know nothing of the first; port scanners and osquery do the first
and cannot do the third; image scanners live entirely on the other side of the
second; and the fourth is usually the job of an eBPF agent running resident on
the host, not of a one-shot binary reading ELF headers offline.

Three more things follow from taking that seriously, and I have not seen them
together elsewhere either:

- **Stopped containers are inventoried too.** They serve nothing - but a
  stopped `postgres:14` still holds 142 packages with the same advisories, and
  it will be up again.
- **Every finding carries its evidence and a confidence.** A row saying "port
  443 is nginx 1.24" is indistinguishable from a guess unless it shows its
  working.
- **What could not be seen is machine-readable.** `scan.exposure_blind_spots`
  names it, because a host running Kubernetes NodePort or Docker with
  `userland-proxy` disabled otherwise produces a document identical to a host
  with nothing exposed at all.

None of this makes `swinv` better at what those tools are for. It does not
match CVEs, it has no dashboard, and it will never know your fleet. It answers
one question they leave to you: **what is reachable on this machine, and
exactly which package is behind it.**

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

Every write is atomic - temp file, `fsync`, `rename` - so a collector can never
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
| `--no-services` | false | Do not report what is listening |
| `--no-containers` | false | Do not identify containers or what they run; also stops swinv talking to the container runtime |
| `--no-service-command` | false | Linux: keep the services block, drop the command lines |
| `--since PATH` | - | Diff against a previous report |
| `--heartbeat` | false | NDJSON: a digest every scan, components only when they change |
| `--elf-scope MODE` | listening | Read shared-library links: `listening`, `all`, or `off` |
| `--config-scope MODE` | standard | Collect cron, systemd units, SUID, tasks, autoruns |
| `--elf-symbols` | false | Record imported symbol lists, not only counts |
| `--ndjson-include LIST` | - | NDJSON also carries `exposure`, `containers`, `links`, `config`, or `all` |
| `--transmit URL` | - | Also POST the scan to a Riskability server; the files are still written |
| `--hash` | false | Record a SHA-256 per component |
| `--fast` | false | Scan at normal priority and full parallelism (see below) |
| `--max-memory SIZE` | - | Soft memory limit, e.g. `1536MiB` |
| `--debug-stacks-after DUR` | - | Dump goroutine stacks if the scan is still running, for a run that appears hung |
| `--timeout DURATION` | `30m` | Whole-run deadline |
| `--verbose` / `--quiet` | false | Per-stage timing / silence |
| `--full-scan` | false | Windows: also enumerate the filesystem and read manifests |
| `--volumes LIST` | `C:` | Windows: volumes to enumerate, e.g. `D:` or `D:,E:` - replaces the default |

**[Full flag reference and exit codes →](docs/FLAGS.md)**

### swinv gets out of the way by default

An inventory collector is background maintenance: it runs unattended, on a
timer, on machines doing real work, and nobody is waiting for its answer. So by
default swinv runs at `nice 10` with idle I/O priority on Linux, in background
priority mode on Windows, and with a quarter of the CPUs as cataloger workers.
Worker count matters here beyond speed - it sets how deep an I/O queue the scan
presents to the kernel, and that is most of what decides whether the rest of the
machine feels slow while it runs.

It costs about a third of the runtime: `/usr` on an 8-core host took 41.6 s by
default and 30.6 s with `--fast`. Pass `--fast` when a person is waiting.

All human-readable output goes to **stderr**; only `--stdout` data goes to
stdout. Exit codes distinguish complete (`0`), partial (`1`), usage (`2`), fatal
(`3`) and timeout (`4`) - a single failing cataloger never aborts a run, because
an inventory missing one ecosystem beats no inventory.

## What is skipped by default

Exclusions are what make a scan take minutes instead of hours, so the defaults
are opinionated:

- Kernel and volatile trees: `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp`,
  `/var/cache`, `/var/log`, `/var/spool`, `/var/crash`.
- Container and orchestrator storage: `/var/lib/{docker,containers,containerd}`,
  `/var/lib/kubelet/pods`.
- Build and VCS noise: `**/.git/**`, `**/__pycache__/**`, `**/.cache/**`.
- **Every mount that is not a local filesystem** - NFS, CIFS, sshfs, autofs,
  overlay, squashfs - read from `/proc/self/mountinfo`. Walking a mounted NFS
  share is the single biggest cause of a scan taking hours. Disable with
  `--no-auto-exclude-mounts`.
- **`/home` and `/root`.** On the machine this was built on, `/home` alone was
  508,687 files across 86 `node_modules` trees - more than the rest of the
  filesystem combined. Home directories are also per-user, high-churn and
  privacy-sensitive, none of which is true of the machine's own software.
  `--include-home` turns them back on.

**Snap and Flatpak are scanned** - they are genuinely installed software. Snaps
are squashfs loop mounts, so `swinv` specifically carves `/snap` and
`/var/lib/snapd/snap` out of the "skip non-local filesystems" rule; a squashfs
image mounted anywhere else stays excluded. `--no-snap` / `--no-flatpak` opt out.

Whatever is skipped is always recorded in `scan.excluded`, with a note in
`scan.warnings`. Nothing is dropped silently.

## Change detection

`--hash` adds a SHA-256 of each component's primary file. Files backing *more
than one* component are deliberately not hashed - most debs cite
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

## How often to run, and what it costs

The default scan is cheap enough to run often; the heavy flags are not, and
the honest way to choose a cadence is by how much the machine changes:

- **On systems that change often or without control** - developer machines,
  terminal servers, anything users install onto - run often. `--heartbeat`
  makes frequency nearly free on the wire: an unchanged scan writes one
  digest line plus the exposure, container and config records (116KB
  measured), and a change streams in full on the next tick.
- **On stable systems** - servers, OT and appliance-like machines - run
  seldom on a timer, and ad hoc after software updates. Nothing in swinv
  needs to run continuously; the report is the state of the machine at scan
  time, and a machine that does not change has the same report tomorrow.

What the flags cost, measured on a 20-logical-processor laptop with
real-time antivirus (background mode; `--fast` trades politeness for speed):

| Configuration | Wall clock | The machine while it runs |
|---|---|---|
| default scan (registry + listeners, Linux: package DBs) | seconds to ~15 min | barely visible |
| `--full-scan --hash` (Windows) | ~10-14 min | moderate, mostly antivirus |
| + `--elf-scope all --elf-symbols` | + ~21 min for 46k binaries | **~26% CPU**, paced, progress every 30s |

The probe pays for politeness with wall clock: every file open is scanned by
the antivirus at its own priority, so the probe paces itself rather than
turning the AV into a foreground workload. Give the heavy combination
`--timeout 45m`; the probe gets its own equal budget on top, and if it ever
runs out it delivers everything probed so far and says `PARTIAL` in
`scan.warnings` rather than pretending.

## Security and privacy

Worth knowing before you roll this out fleet-wide:

- **No inventory data is transmitted unless you ask for it.** Without
  `--transmit`, `swinv` opens no sockets to send results anywhere. With it, the
  scan is POSTed to the single HTTPS endpoint you named, gzipped, authenticated
  by a bearer token or a client certificate - including passphrase-protected
  PKCS#8 keys, with the passphrase from a TPM-sealable systemd credential
  rather than a flag. Verification is the system trust store, your own CA
  bundle, or a pinned public key (`--transmit-pin`) for the estate whose CA
  cannot reach the trust store; `--transmit-check` validates endpoint, auth,
  TLS and clock in one command before any scan runs; and a scan whose sources
  failed is not transmitted at all by default, because a partial inventory on
  a server reads as a healthy small host. The report files are still
  written locally in every case. The other exception to "no network at all" is a
  best-effort reverse-DNS lookup that fills `host.fqdn` - a normal name
  resolution against your configured resolver, bounded to two seconds and never
  fatal. It carries no scan data, but it does tell that resolver the host
  looked itself up. **`--offline` disables it**, making the run completely
  network-silent at the cost of one field. It is skipped automatically whenever
  `--root` is not `/`.
- **It records host identity**: hostname, `/etc/machine-id`, boot ID, kernel,
  DMI vendor/product, and non-loopback IPs and MAC addresses. That is what makes
  reports joinable across a fleet - but it means the files identify the machine.
  DMI serial and UUID are root-only and simply absent otherwise.
- **It records installed software paths.** With `--include-home`, that includes
  paths inside users' home directories. This is the main reason home directories
  are off by default.
- **It talks to the container runtime, if one is there.** Naming the software
  inside a container means asking the local Docker engine over its Unix socket
  or named pipe - the only route into a stopped container, and the only route
  into any container from Windows. It reads the container list and files from
  container filesystems; it never creates, execs or attaches. This is local
  kernel IPC, not network activity: no address, no route, nothing leaves the
  machine. Reaching the socket implies membership of `docker`/`docker-users`,
  which is itself a privileged position on the host. `--no-containers`
  disables it.
- **It records service command lines.** The `services` block includes each
  listening process's `argv`, and command lines are where secrets end up - a
  `--password` on a daemon's ExecStart, a connection string with credentials in
  it. Anything visible in `ps` can therefore reach an inventory file that gets
  copied elsewhere. **`--no-service-command`** drops that field - and the
  command lines in the configuration surface (cron lines, `ExecStart`) with
  it, keeping the joinable executable paths; **`--no-services`** drops the
  services section.
- **Protect the output directory.** `--out` is created `0755` and files `0644`,
  so an inventory is world-readable by default. Tighten it if your threat model
  needs that.
- **The systemd unit is hardened but deliberately not sandboxed from the
  filesystem.** It sets `ProtectSystem=strict`, `ReadWritePaths=/var/lib/swinv`,
  `PrivateTmp`, `NoNewPrivileges`, and the `ProtectKernel*` / `ProtectClock` /
  `ProtectControlGroups` family. It pointedly does *not* set `ProtectHome`,
  `PrivateDevices`, `PrivateUsers` or `ProtectProc=invisible` - each would hide
  something the scan needs, and the unit documents why inline. Reading the whole
  tree is the tool's entire job.
- **No GPL/AGPL/LGPL anywhere in the dependency tree**, enforced by a CI gate
  that fails the build. See [licensing](#licensing).

## Performance

Two real machines, scanned two minutes apart on the same day, everything
enabled:

| | Windows 11 laptop | Ubuntu 26.04 server |
|---|---|---|
| components | 7,978 | 15,562 |
| exposure rows | 160 | 60 |
| containers | 7 (all stopped) | 16 (12 running) |
| NDJSON | 7.3 MiB | 14.8 MiB |

### How long it takes

At default scheduling priority - `nice 10` with idle I/O, **not** `--fast` -
across repeated runs on those two machines:

| Scan | Runs | Median | Range | Components |
|---|---|---|---|---|
| Linux `/` | 3 | **5m50s** | 5m16s - 6m18s | ~14,400 |
| Linux `/` with `--include-home` | 4 | **9m51s** | 9m28s - 9m57s | ~23,500 |
| Windows, registry only | - | **126 ms** | - | 502 |
| Windows `--full-scan` | 4 | 14m11s | **2m26s - 15m35s** | ~7,900 |

Linux is predictable: repeat runs land within a minute of each other, and
peak RSS is near 2.3 GB. `--include-home` costs about four extra minutes and
9,000 components, almost all of it `~/go/pkg/mod` and `node_modules` - build
caches rather than installed software, which is why home is excluded by
default.

**Windows `--full-scan` is not predictable, and the spread is the finding.**
Four runs on one laptop, same machine, near-identical component counts, and a
**6.4× spread** between fastest and slowest. That is Defender inspecting every
file swinv opens and the state of its scan cache - not anything swinv does
differently. Which is exactly why the Windows default reads the registry, the
package repository and the component store and opens **no file at all**: the
126 ms path is the one you can schedule hourly, and `--full-scan` is opt-in for
when you want the executables on disk as well.

A fleet server with a couple of thousand packages and no source trees is a
very different shape from either - measure your own before drawing
conclusions.

**The heartbeat is where the fleet arithmetic changes.** Components are 99%+
of the stream on both machines, so an unchanged scan collapses to almost
nothing while still reporting what is listening:

| | full scan | unchanged, with `--heartbeat` |
|---|---|---|
| Windows | 7.3 MiB | **48.9 KiB** (99.35% smaller) |
| Linux | 14.8 MiB | **33.7 KiB** (99.78% smaller) |

The remainder is the exposure and container records, which are deliberately
still sent: a port opening is exactly the kind of change that happens while
installed software does not.

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

Scanning `/` walks into **any second root filesystem stored on the disk** - an
extracted tarball, a container rootfs backup, a chroot, a VM image, or a test
fixture - reads its package database, and reports those packages as installed.

Each such component records the root it came from in `root`, and has the
distribution claim stripped from its PURL - a Debian 12 `openssl` inside a snap
base is reported as `pkg:deb/openssl@3.0.11-1~deb12u2` rather than as an Ubuntu
package, because asserting the scanning host's distribution over it would make
both "is it affected" and "is it fixed" meaningless. Where the nested root
states its own release, `attributes.root_os_id` and `root_os_version_id` carry
it.

What remains is that those packages are still *reported*, which is usually
right - a base snap is real software on the machine - but means a count of
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
it to a scanner - for example Anchore's [`grype`](https://github.com/anchore/grype),
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
  means you can tell "the machine changed" from "the advisories changed" -
  which is exactly what `--since` answers.
- **`grype` needs the network to fetch and refresh its database.** `swinv
  --offline` performs no network activity whatsoever, which matters on
  air-gapped or egress-restricted fleets. Collect the SBOMs and match them
  somewhere with connectivity.

Verified end to end on Fedora 44: a 568-component CycloneDX document was
accepted by `grype` v0.117.0, which resolved both `rpm` and `go-module`
components and returned **234 vulnerability matches**. That is a stronger
result than "it parsed" - CVE matching is a join on package identity, so it
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
[`AUTHORS`](AUTHORS) - each retains copyright in their own work and licenses it
to everyone under Apache-2.0. There is no CLA and no copyright assignment. The
trade-off is deliberate and worth stating plainly: because no single party owns
the whole work, `swinv` **cannot be relicensed or dual-licensed** without the
agreement of every contributor. That is the protection community ownership
buys.

Syft is Apache-2.0, so importing it imposes no copyleft obligation; attribution
is in [`NOTICE`](NOTICE). **No GPL, AGPL or LGPL module may enter this binary** -
linking one in would force the whole combined work under the GPL. CI enforces
that with a hard gate (`make license-check`) that fails on any dependency whose
licence is copyleft or unidentified. Of 278 dependencies, none is copyleft.
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) is generated, not
hand-written.

## Architecture

```
cmd/swinv/          flags, wiring, exit codes - thin
internal/model/     output types + schema version. Stdlib only.
internal/hostfacts/ machine identity, read straight from kernel interfaces
internal/scan/      the Syft integration - the ONLY package that imports Syft
internal/wincollect/ the Windows collector: registry, Appx, servicing, MFT
internal/service/   what is listening, and what is behind it
internal/dockerapi/ the container runtime client - the ONLY package that
                    talks to a daemon
internal/ctrpkg/    package databases read from inside a container
internal/output/    JSON, CSV, NDJSON, CycloneDX writers + atomic writes
```

Two packages are deliberately the only door to something. `internal/scan` is
the only one permitted to import Syft, which keeps a Syft API break contained
to one package. `internal/dockerapi` is the only one that talks to a daemon,
which keeps that exception visible and reviewable rather than spread around.
Everything downstream operates on `internal/model` types.

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
remediation. No vulnerability scanning - swinv produces the inventory and the
SBOM; matching them against advisories is a separate job with a database that
moves daily. No macOS support. No TUI.

Not a container scanner, either. It reads the package database of a container
that has a network endpoint, because that is part of this machine's attack
surface; it does not walk container filesystems or unpack images. A full walk
of one container rootfs on the development host ran past ten minutes without
finishing, which is the measurement that settled it.

It reads no firewall, NAT table or security group, so nothing it reports is a
statement about reachability - `bind_scope` describes a bind, and
`scan.exposure_blind_spots` names what could not be seen.
