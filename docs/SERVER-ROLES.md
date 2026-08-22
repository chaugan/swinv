# Server-role detection — design

> **Status: phase 1 implemented.** The socket → process → unit spine is built
> and runs against real `/proc`; the `services[]` schema, IIS, and everything
> below it are not. Measurements marked **Measured** are real; the rest is
> still reasoning.
>
> Every other document in `docs/` describes behaviour that ships and has been
> run against real hosts. This one describes something that does not exist yet.
> It is kept to the same standard in one respect: the measurements in it are
> real, taken on a live Linux host and in containers, and where a measurement
> contradicted the design the design changed rather than the measurement.

`swinv` reports what is *installed*. This document is about what is *running and
serving*, and about deducing the product and version behind it.

## Why this is a different axis

An installed package and a listening service are different risk statements.
`nginx` present in `dpkg` is a patch obligation. `nginx` bound to `0.0.0.0:443`
is an exposure. The same inventory line means different things depending on
whether anything is behind it, and nothing in a package database says which.

The gap runs in both directions, and the second direction is the interesting
one:

- Software installed but not running — most of a typical inventory. Real, but
  not reachable.
- **Software running but not installed** — an application server unpacked into
  `/opt`, a vendor binary in `/usr/local`, a container image with its own
  userspace. Package-based inventory cannot see these at all, and they are
  disproportionately the things nobody is patching.

Surfacing the second class is the strongest argument for building this.

### Why it has to be collected locally, offline

In an air-gapped environment there is no scanner on another host to ask, and no
vulnerability feed to consult at scan time. Both constraints point the same way:
collect locally, decide later.

That has a consequence for the schema. Reachability context cannot be
reconstructed afterwards from a package list — a connected machine holding the
report has no way to learn that `openssl` was loaded into a process listening on
`:443`. If it is not captured at scan time it is gone. Prioritisation data must
therefore travel *inside* the report, alongside the identity data that CVE
matching needs.

## What "serving" means

The definition is not obvious, and getting it wrong makes the output
untrustworthy in ways that are hard to see. The proposal:

| Case | In scope | Why |
|---|---|---|
| TCP in `LISTEN` | **yes** | Unambiguous |
| UDP bound socket | yes, marked | No listen state exists; a bound socket is the best available signal |
| Unix domain socket | yes, marked | Real services (databases, `php-fpm`) are reached this way and nothing else records them |
| systemd socket activation | yes, marked | `systemd` holds the socket and the service may not be running; that is a distinct and useful state |
| Kernel-mode listener (`HTTP.sys`) | yes, special-cased | See the IIS section — there is no user process to attribute |
| Outbound connections | no | Not serving |
| Firewall-blocked listeners | yes, unmarked | swinv does not read firewall state and must not imply it has |

Anything marked is reported with its qualifier attached, never flattened into a
plain "listening" claim.

## The spine, on Linux

The pipeline is socket → PID → executable → component. It needs no external
tools — no `ss`, `netstat`, `lsof`, no D-Bus — which matters for minimal
containers and hardened hosts where none of those exist.

**Measured on a live host**, each step:

```
/proc/net/tcp        state 0A (LISTEN)  ->  local address + socket inode
/proc/<pid>/fd/*     readlink "socket:[188093446]"  ->  pid 4145562
/proc/<pid>/exe      -> /usr/bin/node
/proc/<pid>/cgroup   -> 0::/system.slice/herdr.service
```

The cgroup line is worth dwelling on. It gives the owning systemd unit with a
single file read, no D-Bus connection and no `systemctl` invocation, and it
works for container scopes too (`0::/system.slice/docker-<id>.scope`). Unit name
is the single most useful label for a service, and this is the cheapest possible
way to get it.

It is also worth noting what the very first listening socket on the test host
resolved to: `/usr/bin/node`. The hard case is not an edge case. It is the first
thing you hit.

### Attribution: joining an executable to a component

When a package owns the executable's path, the service attaches to an existing
component and inherits its PURL, version and CPEs — the identity CVE matching
needs, for free. When nothing owns the path, that is not a failure. That is the
finding: serving software outside package management.

**This was designed wrong, and building it proved so.** The plan was to match
the executable against each component's `locations`, which `swinv` already
records. Locations are a component's *evidence* files, not its contents: a deb
records `/var/lib/dpkg/status` and its own `.list`, never `/usr/sbin/sshd`. On
the first end-to-end run, all 30 attributable services on a normal Ubuntu server
came back as unmanaged software — `sshd`, `postgres`, `chronyd`, `systemd`,
`docker-proxy`, every one of them. Not a missing answer: a confident wrong one,
in the exact direction the section exists to avoid.

The file lists do exist, in the package databases, and Syft already parses them
into `DpkgDBEntry.Files` and its `Rpm`/`Apk`/`Alpm` equivalents. What is not
affordable is indexing them: a normal server's run to hundreds of thousands of
paths, and building that map to answer forty questions costs tens of megabytes
in a tool that advertises `--max-memory`.

So the order is inverted. The socket snapshot is taken **before** the scan, the
few dozen executable paths it produces are handed to the scan as a probe, and
the catalogers test membership as they enumerate. Cost is proportional to the
question rather than to the machine, the answer is exact, and a path that was
not probed stays distinguishable from a path that no package owns.

The same run, after: 27 high, 3 medium, 1 low. The three mediums are real —
a binary under `/opt`, and two copies of `/usr/local/bin/node`.

Components in a nested root are excluded from the join, for the reason
`applyFileOwnership` already excludes them: the path a hit matched is a path
inside that tree, not on the host.

**And the two sides disagree about the same file.** On Ubuntu 24.04, dpkg
records `netcat-openbsd` as owning `/bin/nc.openbsd`, while `/proc/<pid>/exe`
reports the running process as `/usr/bin/nc.openbsd`: the kernel resolves the
`/usr` merge symlink, the package database preserves the path from before the
merge. A string comparison misses, and a running `nc` is reported as software
no package manager installed. Caught by CI on a runner rather than by any unit
test, because both sides of it were written from the same wrong assumption.

Both sides are now canonicalised through the merge — but only for the
directories that are *actually* symlinks under the scan root, checked with one
`lstat` each. On Alpine `/bin` is a real directory, `/bin/busybox` and
`/usr/bin/busybox` are different files, and folding them together would invent
a match rather than find one. Verified on both.

## Where the spine breaks

Three cases, all of which the naive pipeline gets wrong. Each was checked rather
than assumed.

### 1. Containers — measured, and it produces a *wrong* answer, not a missing one

Running `nginx:alpine` under Docker and inspecting from the host:

| Signal | Value |
|---|---|
| `/proc/<pid>/exe` | `/usr/sbin/nginx` |
| Does that path exist on the host? | **No** |
| Read via `/proc/<pid>/root/usr/sbin/nginx` | `nginx/1.31.2` — exact match to truth |

`/proc/PID/exe` yields a path in the *container's* mount namespace. Joining it
against host components finds nothing — or, on a host that also has nginx
installed, silently attributes the container's service to the host's package and
reports the wrong version with full confidence.

Resolving through `/proc/PID/root` reaches the real binary and gives the right
answer. So container services can be inventoried from the host, offline, with no
Docker API and no container runtime cooperation — but only if every path
traversal goes through `/proc/PID/root`, and only if the result is labelled as
the container's rather than the host's.

This was very nearly written into this document the wrong way round. The
reproduction caught it.

### 2. Interpreted and JVM daemons — the exe is the wrong object

For `java`, `python3` or `node`, `/proc/PID/exe` identifies the runtime, not the
product. Tomcat's version is not in the JVM binary and never will be.

The evidence lives in launch context and deployed artifacts:

- `/proc/PID/cmdline` — `-jar`, `-cp`, `@argfile`, `-Dcatalina.home`,
  `-Dcatalina.base`, `python -m gunicorn`, `node server.mjs`
- `/proc/PID/cwd` — resolves relative paths in the command line
- deployment roots — `WEB-INF/lib`, `BOOT-INF/lib`, `META-INF/MANIFEST.MF`
  (`Implementation-Version`), Maven `pom.properties`, Spring Boot
  `META-INF/build-info.properties`, Python `*.dist-info`

Those roots are directories full of dependencies, which is to say they are
exactly what `swinv` already scans well. The right move is not to write a Tomcat
parser but to point the existing catalogers at the deployment root and attach
the resulting components to the service.

One correction worth recording, because the opposite is tempting: **do not use
`/proc/PID/maps` to find loaded JARs or Python modules.** `maps` shows native
mappings. It does not see the logical dependency graph of a managed runtime, and
a design that relies on it will quietly under-report.

### 3. IIS — there is no process to attribute

This is the motivating example and it does not fit the spine at all.

IIS does not listen on port 443. **`HTTP.sys`, a kernel-mode driver, owns the
socket.** Requests are routed to `w3wp.exe` worker processes started by WAS from
`applicationHost.config`. Following socket → PID on a Windows web server
attributes the site to `System`, which is true and useless.

The authoritative source is configuration, not runtime state:

| Source | Gives |
|---|---|
| `%windir%\System32\inetsrv\config\applicationHost.config` | sites, bindings, application pools, virtual directories, physical paths, installed modules |
| `HKLM\SOFTWARE\Microsoft\InetStp` | `VersionString`, `MajorVersion`, `MinorVersion` |
| `%ProgramFiles%\dotnet\shared\*` | installed .NET runtimes |
| app pool → `w3wp.exe` mapping | which sites are actually running |

Reading `applicationHost.config` gives the entire IIS topology **offline,
without touching a socket** — which suits an air-gapped scan better than
anything runtime-derived. The listener is then modelled as *evidence that IIS
owns this endpoint*, not as a process attribution.

The physical paths are the prize. They point at deployed web applications, whose
third-party dependencies are ordinary components that existing catalogers can
enumerate — and which are usually the least-patched software on the machine.

## Determining the version

The original proposal here was that any daemon serving a version banner over the
network must contain that banner as a literal string, so read-only string
extraction would cover exactly the class of software this feature cares about.

**That was tested and is only partly true.** Measured against ground truth:

| Binary | Extracted | Truth | Verdict |
|---|---|---|---|
| `sshd` | `OpenSSH_10.2p1` | `OpenSSH_10.2p1` | exact |
| `postgres` | `PostgreSQL 18.4` | `PostgreSQL 18.4` | exact — **plus a false positive** |
| `dockerd` | *(nothing)* | `29.6.0` | fails |
| `node` | *(nothing)* | `22.22.1` | fails |

Two distinct failure modes, and both matter.

**False positives from prose.** The `postgres` binary also yields
`PostgreSQL 9.1`, from the string *"This is caused by an incomplete page split at
crash recovery before upgrading to PostgreSQL 9.1."* A version-shaped string is
not a version. Anchored per-product patterns are necessary but not sufficient,
because the anchor appears in error messages too.

**Whole classes with no banner.** Go binaries carry their version in `-ldflags`,
not a banner — `dockerd` embeds `dockerversion.Version=29.6.0` inside the
ldflags string, which is parseable but is not the same technique. Interpreters
have no product version to carry, because the product is not the binary.

Beyond that, banners can be turned off (`server_tokens off`, Apache
`ServerTokens`), rewritten by distributions, or changed by forks.

**Conclusion: string extraction is one evidence source, never the foundation.**

### The evidence ladder

Sources in descending order of trustworthiness. Each is offline and read-only.

| # | Source | Confidence | Notes |
|---|---|---|---|
| 1 | Package database ownership of the exe path | high | Already collected. Exact PURL and version. |
| 2 | `.note.package` ELF note | high | Exact, and works outside the package DB — see below |
| 3 | Go build info (`debug/buildinfo`) | high for deps | Exact dependency tree; main module is often `(devel)` |
| 4 | PE `VERSIONINFO` (Windows) | medium-high | What Syft already uses |
| 5 | Deployed artifact metadata | medium-high | `MANIFEST.MF`, `.dist-info`, `pom.properties` |
| 6 | Config files | medium | `applicationHost.config`, `server.xml`, `nginx.conf` |
| 7 | Anchored banner strings | **low** | Per the measurements above |
| 8 | Allowlisted version probe | medium | Opt-in only — see below |

### The ELF package note: exact identity from the binary itself

Binaries built by some distributions carry a `.note.package` section holding
JSON that names the owning package — the systemd ELF packaging metadata
convention:

```console
$ readelf -n /usr/sbin/sshd
Displaying notes found in: .note.package
  FDO   0x00000068  FDO_PACKAGING_METADATA
    Packaging Metadata: {"type":"deb","os":"ubuntu","name":"openssh",
                         "version":"1:10.2p1-2ubuntu3.5","architecture":"amd64"}
```

This is exact, needs no package database, and — critically — **survives being
copied out of package management and into a container**, which is precisely
where the package DB cannot help.

Coverage is the question, so it was measured rather than assumed:

| Distribution | ELF binaries in `/usr/{bin,sbin}` carrying the note |
|---|---|
| Ubuntu 26.04 | **97%** (424/436; 1762/1790 on a full host) |
| Fedora 43 | **95%** (508/534) |
| Debian 13 | 36% (106/289) |
| Debian 12 | 0% |
| Rocky 9 | 0% |
| Alpine 3.22 | 0% |
| Arch | 0% |
| openSUSE Tumbleweed | 0% |

So: a primary source on Ubuntu and Fedora, partial on Debian 13, absent
everywhere else. **Use it when present, never depend on it.**

*Method note, for honesty: coverage was measured by grepping for the note's JSON
payload rather than parsing section headers, verified against `readelf` on a
sample. The 0% and 95%+ results are unambiguous; treat the Debian 13 figure as
approximate.*

The exceptions on Ubuntu are also informative — `cloudflared`, `containerd-shim`,
`ctr`, `docker`, `snap` — third-party Go binaries not built by the distribution's
toolchain. Absence of the note correlates with exactly the unmanaged-software
class this feature exists to surface. It is a weak signal rather than a reliable
one, since glibc utilities lack it too, but it is worth recording.

## Evidence, not deduction

The requirement is to "deduce the product and version behind" a listening port.
The design deliberately does not do that as a single inferred answer.

A service finding is an **evidence graph**, and the derived conclusion carries
its confidence and its basis:

> Port 443 is bound by `HTTP.sys`. `applicationHost.config` binds site `Foo` to
> `*:443:`. App pool `FooPool` maps to `w3wp.exe` PID 4812. Its physical path is
> `D:\sites\foo`, which contains `BOOT-INF/lib` with 84 components. IIS version
> `10.0` comes from `HKLM\SOFTWARE\Microsoft\InetStp`.

That survives messy reality. A single field claiming *"port 443 → IIS 10.0"*
does not, and worse, it is indistinguishable from a guess once it reaches a
consumer. Every service finding therefore carries `confidence`, the `evidence`
that produced it, and its known `limitations`.

This is the difference between a tool whose output can be trusted at scale and
one that is right most of the time in ways nobody can check.

## Executing binaries: never by default

Running `nginx -v` on a discovered binary is the obvious way to get a version.
It is also a code-execution primitive in a tool that runs as root on a timer.
A version command can load configuration, plugins and shared libraries from
paths an attacker may control, and the binary may simply be malicious. An
inventory collector that executes what it finds has become a lateral-movement
tool.

**Default: passive only. Nothing discovered is ever executed.**

An opt-in `--probe-versions` is nonetheless worth having, because the coverage
it buys is concentrated exactly where the passive ladder is weakest: bespoke and
vendor installs under `/opt` and `/usr/local` that no package database describes.
For distro-packaged software it adds almost nothing.

If built, the boundaries are not negotiable: a fixed allowlist of
(basename, argv) pairs owned by the detector rather than the operator, absolute
paths only, no shell, scrubbed environment, a hard timeout, a read-only working
directory, dropped privileges where the platform allows, and every probe
recorded in the evidence as `active_probe`.

## No network activity, including localhost

A localhost connect would resolve real ambiguity — HTTP `Server` headers, TLS
certificates, SSH handshakes, database greetings. Nmap's service fingerprints
are good prior art for turning such responses into product and version.

It is still the wrong default. Connecting to a service writes to its logs, can
trip intrusion detection, can hit an administrative endpoint, can consume a
connection from a saturated pool, and can hang. "Not the internet" is not the
same as "not a network operation".

Passive stays the default. The schema should carry an `evidence.type` field from
day one so active probing can be added later without a schema break, rather than
being designed out permanently.

## Loaded-versus-installed drift

`/proc/PID/maps` marks a mapping whose backing file has been replaced as
`(deleted)`. That detects a specific and under-reported condition: **the package
was patched, but the running process still has the old code mapped.** It makes
"we patched it" false, and no package inventory can see it. `checkrestart` and
`needrestart` work this way.

This was proposed as a headline feature. Then it was measured, and the
measurement is a warning:

```
5 processes with deleted mappings, of which 5 were false positives:
  /var/tmp/.894189a34e08df87-0.node (deleted)   <- JIT-extracted native module
  /dev/shm/sem.Rt4And (deleted)                 <- POSIX semaphore
```

A naive implementation would have reported "5 processes running replaced code"
with a 100% error rate. Node.js unpacks native addons to temp files and unlinks
them; POSIX semaphores appear as deleted mappings by construction.

The signal is real but requires filtering: file-backed, executable mappings,
whose path lies inside a package-owned directory, excluding temp and shared
memory. Report as `restart_required` with the specific files listed, never as a
bare count. On Windows the equivalent — `EnumProcessModules` plus pending-reboot
registry keys — is weaker, and in-place overwrite and static linking cause false
negatives on both platforms.

Ship it scoped, with its limitations attached to the finding.

## Privilege

Measured, on a container's `nginx` process, as a non-root user versus root:

| Path | Unprivileged | Root |
|---|---|---|
| `/proc/PID/cgroup` | readable | readable |
| `/proc/PID/exe` | **empty** | `/usr/sbin/nginx` |
| `/proc/PID/root` | **empty** | traversable |
| `/proc/PID/fd/*` | **empty** | readable |

Unprivileged, the socket → PID join fails for any process the user does not own,
which on a server is nearly all of them. The cgroup path still resolves, so
*some* attribution survives — enough to name the unit, not enough to identify the
binary.

An unprivileged run must therefore set `scan.incomplete`, warn explicitly that
service attribution was partial, and never emit a confident-looking service list
that silently covers only the current user's processes.

## Schema

A new top-level `services[]` array, schema `1.5` → `1.6`, additive. **Shipped**;
the field reference is in [OUTPUT.md](OUTPUT.md#services).

A service is a **relation**, not a property of a component: one `nginx` backs
many sites; one service involves the daemon, the OpenSSL it has loaded, and the
application it serves. Putting a `role` field on `Component` collapses a
many-to-many reality into a one-to-one lie.

Each entry carries endpoints, process and unit identity, evidence, confidence,
and references to component identities.

**The one real risk with this shape**: most CVE matchers ignore `services[]`
entirely. The mitigation is a rule — *vulnerable software is always also a
normal component*. Services reference components by identity; they never become
the only place a piece of software appears. A consumer that ignores `services[]`
loses context and loses nothing else.

- **CycloneDX** already models this: `services[]` with `endpoints`, and
  `dependencies` linking services to components. No invention needed.
- **CSV** gets a separate `-services.csv` rather than new columns, denormalised
  for SIEM ingest: endpoint, pid, unit, product, version, component PURL,
  confidence. The component CSV is a flat table of components; a service is a
  different shape and wedging it in would corrupt both.

## Phasing

| Phase | Work | Why this order |
|---|---|---|
| 1 | ~~Linux socket → PID → exe → component, with cgroup unit labelling and container resolution~~ **Done** | The spine. Cheap, no dependencies, and immediately surfaces unmanaged serving software |
| 2 | ~~`services[]` schema, CycloneDX services, `services.csv`, confidence and evidence model~~ **Done** | Proves the shape before more collectors depend on it |
| 2.5 | ~~Network exposure: host-namespace socket list, bind scope, publish indirection, container identity from the container's own package database, blind spots as data~~ **Done** | The question the whole design was for: what is reachable, and what software is behind it |
| 3 | IIS vertical slice: `applicationHost.config`, `InetStp`, app pool → `w3wp` | The motivating case. Early, because the generic pipeline is weakest here and waiting would demo badly |
| 4 | Interpreted and JVM: launcher classification, deployment-root scanning | The largest coverage gain and the most work |
| 5 | Drift detection, scoped and filtered | Valuable, independent, and safe to defer |
| 6 | `--probe-versions`, if the passive ladder proves insufficient | Only with evidence that it is needed |

Phase 1 alone is worth shipping. It answers "what is listening, and does
anything own it" — which no package inventory can answer at all.

## Measured: the spine, running

Built as `internal/service` and run against a live host. Everything comes from
`/proc`: no `ss`, no `netstat`, no `lsof`, no D-Bus, so it works in a minimal
container and on a hardened host.

| | unprivileged | as root |
|---|---|---|
| listening sockets found | 44 | 44 |
| attributed to a process | 6 | **31** |
| unattributed | 38 | **0** |

The privilege boundary is exactly as predicted: `/proc/net` is world-readable so
the endpoints are always found, but `/proc/<pid>/fd` belongs to the process
owner, so an unprivileged scan attributes only its own. Those sockets are still
reported, with a warning naming the count — "something is listening on 443 and I
could not see what" is more useful than silence.

What it produces on a real machine:

```
pid=1        unit=init.scope                 0.0.0.0:22/tcp [::]:22/tcp6
pid=101813   unit=postgresql@18-main.service 127.0.0.1:5432/tcp [::1]:5432/tcp6
             exe=/usr/lib/postgresql/18/bin/postgres
pid=140868   unit=cloudflared.service        127.0.0.1:20241/tcp [::]:33209/udp6 …
pid=3629839  container=71547eb85e25          0.0.0.0:4632/tcp
             exe=/usr/local/bin/node
```

Four things that confirm the design and one that corrects it.

Grouping by process is right: `postgres` binds v4 and v6 and is one service, not
two. `cloudflared` mixes TCP and UDP on one process. Reporting each socket
separately would misstate how much is running.

The cgroup gives the unit for one file read, with no D-Bus client, and gives the
container id for containerised processes.

The interpreter problem is not an edge case — it is the *first* thing you hit.
Two of the six attributed services unprivileged were `/usr/local/bin/node` and
`/usr/bin/python3.14`, where the executable names the runtime and says nothing
about the product.

**And the correction: port 22 is owned by pid 1.** Socket activation means
systemd holds the socket and the service starts on first connection, so
following socket → process lands on `systemd` for one of the most obviously
interesting ports on the machine. That is now marked rather than reported as a
systemd service, because it is a genuinely different state — the daemon may not
be running at all — and not a failure to resolve one.

## Measured: the shape, shipped

The same host, `--format json,csv,cyclonedx-json`, as root:

```
swinv: services: 27 attributed to installed software, 3 running software nothing installed, 1 unidentified
swinv: wrote svcout/host-20260821T205516.499Z.json
swinv: wrote svcout/host-20260821T205516.499Z.csv
swinv: wrote svcout/host-20260821T205516.499Z-services.csv
swinv: wrote svcout/host-20260821T205516.499Z.cdx.json
```

The three `medium` findings are the point of the exercise: a vendor binary under
`/opt` and two copies of `/usr/local/bin/node`, none of them installed by a
package manager, all of them listening. Nothing in a package inventory says so.

The one `low` is port 22, still correctly marked socket-activated rather than
attributed to `systemd`.

The summary line leads with the high count but the middle number is the one to
read, and the wording says so: *"running software nothing installed"*.

## Measured: the network edge

The same host, as root. 44 host-namespace sockets, 10 containers.

```
exposure: 44   containers: 10
0.0.0.0:80   -> container 9d5a98d0dc04 /usr/sbin/nginx
                pkg:apk/alpine/nginx@1.27.5-r1?arch=x86_64&distro=alpine-3.21.3   high
0.0.0.0:3000 -> container 2864a9b3fa8c /usr/local/bin/node                        medium
```

Container operating systems read from each container's own `/etc/os-release`:
`rhel-8.10`, `alpine-3.21.3`, `alpine-3.24.1`, `debian-12`, `debian-13`,
`wolfi-20230201`, `ubuntu-26.04` — seven distributions on one Ubuntu 26.04
host, each with its own advisory stream.

Four things this measurement settled.

**The image is not an identity.** Every reviewer said so independently, and the
mechanism is checkable: Grype dispatches matchers by ecosystem and has no `oci`
matcher; OSV and OSS Index carry no OCI coordinates; Dependency-Track ingests
the PURL, finds nothing, and renders the component clean — indistinguishable
from analysed-and-safe. The identity comes from the container's own package
database instead, which was already reachable through `/proc/<pid>/root`.

**Cataloguing the container was not affordable.** A full Syft walk of one
container rootfs on this host ran past ten minutes without finishing. Probing
the four executables that are actually listening takes milliseconds, and it is
the same discipline the host join already uses.

**docker-proxy is a configuration, not a mechanism.** It does not exist with
`"userland-proxy": false`, under rootless Docker, or under rootful Podman's
default netavark — and in those configurations publishing is pure netfilter
DNAT with no process and no socket. Discovery is therefore the host namespace's
socket table; the proxy's argv only rewrites a destination when that process
happens to be the one holding the socket.

**A blind spot has to be data.** Without `scan.exposure_blind_spots`, a host
with `userland-proxy` disabled and a host with nothing published produce
byte-identical exposure sections. Prose in `warnings[]` does not survive an
ingest pipeline; a machine-readable array does.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Shell out to `ss`, `netstat`, `lsof` | Absent from minimal containers and hardened hosts; parsing human-readable output is fragile. `/proc` is the same data without the dependency |
| D-Bus to `systemd` for unit mapping | `/proc/PID/cgroup` gives the same answer with one file read and no client library |
| `Win32_Product` for Windows services | Enumerating it triggers MSI repair and can mutate the machine. Disqualified here as it is in `docs/WINDOWS.md` |
| Banner grabbing on localhost | Writes to service logs, can trip IDS, can hang. Kept as a possible opt-in, never a default |
| `/proc/PID/maps` for JVM/Python dependencies | Shows native mappings only; misses the managed dependency graph entirely |
| A `role` field on `Component` | A service is many-to-many with components; the field would be wrong as often as right |
| Deriving services from systemd unit files alone | Says what is *supposed* to serve, not what *is*. Useful as corroborating evidence, wrong as the source of truth |

## Open questions

1. **How is a service identified across runs, for `--since`?** Port numbers move,
   PIDs always change, unit names are stable but not unique per endpoint. Delta
   quality depends entirely on this and it is not solved.
2. **Should a socket-activated but not-running service be reported as serving?**
   It will accept a connection. Nothing is running. Both answers mislead someone.
3. **How much of a deployment root should be scanned?** `WEB-INF/lib` is bounded.
   A physical path of `D:\` is not. This needs the same kind of guard that
   `--full-scan` gets in `docs/WINDOWS.md`.
4. **Does the confidence model survive contact with consumers**, or does every
   downstream tool flatten it to a boolean and reintroduce exactly the false
   confidence it exists to prevent?

---

*This design was reviewed by an independent model, which corrected three
load-bearing assumptions: that banner strings could be the primary version
source, that IIS would fit the socket → PID → exe pipeline, and that opt-in
execution should be ruled out entirely. The measurements throughout were taken
independently and, in two cases — banner coverage and drift false positives —
contradicted the design as originally written.*
