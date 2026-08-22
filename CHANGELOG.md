# Changelog

All notable changes to `swinv` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

`swinv` is `v0.x`: while the tool is tested and in use, the CLI, the output
schema and cataloger coverage may still change between releases. See
[Versioning](#versioning) below.

## [0.4.0] — 2026-08-22

The network edge on Windows, and containers read from the Docker engine.

### Added

- **Windows reports what is listening**, from `iphlpapi` rather than `/proc`.
  `GetExtendedTcpTable` and `GetExtendedUdpTable` return the socket tables with
  an owning pid already attached, so `services[]` and `exposure[]` now exist on
  Windows. The row layouts are parsed by pure functions with tests, because a
  wrong field offset would otherwise show up only on Windows and only as ports
  that look absurd.
- **Containers on Windows are read from the local Docker engine.** A Docker
  Desktop container is a Linux process inside a WSL2 virtual machine: no entry
  in the Windows process table, sockets in a namespace inside the VM, and no
  Windows API that reaches either. Without asking the engine, a published port
  resolves to Docker's own proxy — the non-answer this design exists to avoid.
  This is a deliberate exception to the no-daemon-APIs rule, taken because the
  alternative on Windows is a wrong answer rather than a missing one, and it is
  still true that swinv performs no network activity: a named pipe is kernel
  IPC with no address and no route.

  The engine states its port mappings itself, which is better than parsing them
  out of a forwarding process's argv, so a runtime-supplied mapping now takes
  precedence over that path everywhere.

  What the engine cannot give is the packages inside the container, so those
  services are reported at `medium` with the workload and image named, and
  `container-packages-not-readable` joins the blind spots.

- **`Service.os_component` and `Exposure.os_component`** mark a listener that
  is part of the operating system. Without it `medium` was a lie about a
  Windows service running from `System32`: medium means software running
  outside package management, which is the interesting finding, and an OS
  binary is the opposite of that. A first Windows run produced 65 exposure
  rows and identified none of them, most being `svchost.exe`.

### Fixed

- **Windows could attribute nothing at all.** The join matched an executable
  against a component's recorded locations, but a Windows registry entry
  records the directory a product was installed into — `C:\Program Files\7-Zip`
  — and never the executables under it, so nothing ever matched and every
  listener reported as unmanaged software. The longest containing install
  directory now counts, case-insensitively, graded `medium` because a
  containing directory says the product was installed there rather than that
  it ships that particular file.
- **Sockets with no identifiable process vanished from `exposure[]`.** They
  were counted and then dropped, so a privileged run inside WSL2 reported
  twelve listening sockets and zero exposure rows — a machine described as
  having nothing exposed on the strength of not having been able to look. They
  are now reported without a process against them, which is the statement the
  section exists to make.
- **The unattributed-sockets warning blamed the wrong thing.** It said an
  unprivileged scan sees only its own sockets, which was printed verbatim to a
  user running under `sudo`. There are two causes and the message now names
  both: unreadable open files, or a holder outside this PID namespace — the
  latter being exactly what happens under WSL2.

## [0.3.0] — 2026-08-22

What is exposed at the network edge, and what runs inside the containers.

### Added

- **What is exposed at the network edge, and what is running inside the
  containers**, on Linux, and with it schema `1.7`.

  `exposure[]` is one row per listening socket in the **host** network
  namespace, and nothing else — membership is the verdict, so a consumer
  reading only that array cannot mistake a container's `0.0.0.0` bind for a
  host one. `bind_scope` then says how widely each is bound. Deliberately not
  "public"/"private" and never "internet-facing": swinv reads no firewall, and
  `scan.firewall_examined` is emitted as a constant `false` so that reaches an
  ingest pipeline rather than only the documentation.

  `containers[]` is each container and what it listens on inside its own
  namespace, with the identity that makes this useful:
  `pkg:apk/alpine/nginx@1.27.5-r1` from the container's own package database,
  read through `/proc/<pid>/root`. That is a coordinate Grype and Trivy match
  today. An image reference is not — there is no `oci` matcher anywhere in the
  chain, and Dependency-Track will ingest one, find nothing, and show the
  component as clean, which is indistinguishable from safe. The image digest is
  emitted as a locator on its own field and never as an identity.

  A published port follows into the container behind it, so a host endpoint
  names the software that actually answers rather than the package that ships
  `docker-proxy` — which was 14 of 31 services on the development host.

- **`scan.exposure_blind_spots`** names, in machine-readable form, what could
  not be observed: netfilter DNAT always, plus an unprivileged scan, a
  Kubernetes node whose NodePorts are iptables rules, or a Docker daemon with
  `userland-proxy` disabled. Without it those hosts produce a document
  identical to a host with nothing exposed. swinv does not parse iptables or
  nftables: it would not answer the reachability question even when it
  succeeded, and trading a declared blind spot for an undeclared guess is the
  wrong trade.

- **`--no-containers`** keeps the host services and the exposure list but stops
  swinv reading container filesystems.

- **A `-exposure.csv` sidecar**, one row per host socket, repeating the
  scan-level qualifiers on every row so a denormalised consumer can tell a
  complete row from one produced by a scan that could not look.

### Fixed

- **Containerised processes were attributed to host packages.** Container
  detection only recognised the systemd cgroup driver's `.scope` layout, so
  under the cgroupfs driver — and on Kubernetes, and under LXC — a container's
  process looked like a host process and had its executable matched against the
  *host's* package databases. A container running `/usr/sbin/nginx` on a host
  that also has nginx got the host's package, the host's version, and
  confidence `high`. Detection is now on the shape of the cgroup path, and the
  guard no longer depends on recognising a layout at all: a process in a
  different mount namespace than init is never joined to host packages.

- **CycloneDX output carried no distro.** Syft's decoder — which is what Grype
  uses for `grype sbom:`, a recipe this project documents — reads the Linux
  release only from a `components[]` entry of type `operating-system`, and
  swinv emitted none. Every deb and rpm therefore arrived with no distro, and
  matching fell back to comparing backported versions against upstream
  numbering: the same failure that produced 442 false findings on one host, this
  time caused by the output format itself.

- **What is listening is now part of the inventory**, on Linux, and with it
  schema `1.6`. A new top-level `services[]` array records each listening
  socket, the process behind it, its systemd unit and container, and which
  installed software owns its executable — with a `confidence` and an
  `evidence` trail, because a service finding is assembled from evidence of
  varying strength and a bare claim that "port 443 is nginx 1.24" is
  indistinguishable from a guess.

  The interesting rows are the `medium` ones: software that is serving traffic
  and that no package manager installed. A package inventory cannot produce
  that finding at all. On the development host it is three of thirty-one — a
  vendor binary under `/opt` and two copies of `/usr/local/bin/node`.

  Everything comes from `/proc`: no `ss`, no `netstat`, no `lsof`, no D-Bus.
  Unprivileged it degrades rather than fails, since `/proc/net` is world-
  readable but another process's open files are not; the ports are still
  reported and the count that could not be attributed becomes one aggregate
  entry and a warning. Socket-activated ports are marked as such rather than
  attributed to `systemd`, because the daemon may not be running at all.

  Output: `services[]` in JSON; CycloneDX `services[]` with the schema's own
  `endpoints`, plus `dependencies[]` edges linking each service to the
  components behind it; and a separate `<name>-services.csv` sidecar alongside
  the component CSV. NDJSON carries components only. See
  [docs/SERVER-ROLES.md](docs/SERVER-ROLES.md) and
  [docs/OUTPUT.md](docs/OUTPUT.md#services).
  Paths are compared through the `/usr` merge where it is in effect. dpkg on
  Ubuntu 24.04 records `netcat-openbsd` as owning `/bin/nc.openbsd` while
  `/proc/<pid>/exe` reports `/usr/bin/nc.openbsd`, and a plain comparison
  reports the running `nc` as unmanaged software. Whether each directory is
  actually a symlink is checked rather than assumed, because on Alpine `/bin`
  is real and `/bin/busybox` is not `/usr/bin/busybox`.
- **`--no-services`** skips the whole section, and **`--no-service-command`**
  omits just the `command` field. Command lines are where secrets end up — a
  `--password` on a daemon's ExecStart, a connection string with credentials in
  it — and an inventory file is usually copied somewhere with a different
  audience. [SECURITY.md](SECURITY.md) now says so plainly.
- **Base snaps are recognised as their own filesystem root**, so the components
  inside them stop being attributed to the host. A base snap is a different
  operating system — `core18` is Ubuntu 18.04 while the host may be 26.04, with
  its own package set and its own update cadence — and 862 components on one
  reported host all claimed `root: "/"`. Where a nested root states its own
  release, `attributes.root_os_id` and `attributes.root_os_version_id` now carry
  it, rather than leaving consumers to infer 18.04 from the name `core18`.
- **Python and npm packages are now inventoried on Windows** under
  `--full-scan`. The Linux collector gets roughly forty ecosystems from Syft and
  the Windows collector could get none, because Syft's resolver opens every file
  it indexes — measured as unworkable on Windows, where every open is inspected
  by antivirus. Instead, MFT enumeration already produces every filename without
  opening anything, and installed packages announce themselves by name:
  `*.dist-info/METADATA`, `*.egg-info/PKG-INFO`, `package.json`. Only those files
  are opened. They carry real PURLs, since unlike registry entries these
  ecosystems have canonical PURL types.

## [0.2.3] — 2026-08-21

One reported issue: distribution-installed language packages now name the OS
package that owns them.

### Added

- **`Component.owned_by`** links a distribution-installed language package to
  the OS package that owns its files, and with it schema `1.5`. Syft already
  computes this and swinv was discarding it: the deb's file list contains the
  very `egg-info` path the Python cataloger read. Both rows are still reported —
  the OS package is what the vendor patches, the ecosystem package is what
  upstream advisories are written against — but a consumer assessing the second
  against upstream was comparing a backported version with upstream's own
  numbering. One reported host produced 442 false findings that way, because
  Ubuntu's `cryptography 2.1.4+esm1` is patched while PyPI's `2.1.4` reads as
  thirty-seven releases behind. An empty `owned_by` is equally meaningful: the
  component came from `pip` or `npm` and genuinely should be checked upstream.

## [0.2.2] — 2026-08-21

Four issues reported by someone building an offline vulnerability matcher
against swinv output, and the Windows update model rebuilt on what the
component store actually records.

Two of the four were dangerous rather than untidy: a placeholder version that
parses as a valid low version, and packages in nested roots carrying the
scanning host's distribution. Both produced output that looks like an answer
and is not one, which is the worst way for an inventory to fail.

### Added

- **`Component.root`** records which filesystem root a component was found in —
  `/` for the scanned machine, or a nested root such as a snap base or a
  container layer — and participates in deduplication. Two packages of the same
  name and version in different roots are two installs with two patch states;
  they were previously merged into one row whose `locations` spanned both, so a
  consumer could not tell which root either belonged to. CSV column 19.
- **Store and MSIX packages** and **installed Windows updates**, both from the
  registry, in the default scan.
- **Candidate CPEs on Windows components.** Without a PURL *and* without a CPE
  a component carries no identifier at all, so a CycloneDX document from a
  Windows host matched nothing in any scanner and returned a clean-looking
  empty result.

### Changed

- **Packages found under a nested root no longer claim the host's
  distribution.** Syft stamps every package with the scanned host's distro, so
  a Debian 12 `openssl` inside a snap base arrived as
  `pkg:deb/ubuntu/openssl@3.0.11-1~deb12u2?distro=ubuntu-26.04`. A consumer
  trusting `distro=` compares a Debian version against Ubuntu's fixed versions,
  and both the "is it affected" and "is it fixed" answers are meaningless. The
  distribution claim is now removed rather than corrected: a missing qualifier
  is honest where a wrong one is not.
- **Windows updates are modelled by servicing stream, not as a flat KB list.**

### Fixed

- **`version` is omitted when unknown, instead of the literal `"UNKNOWN"`.**
  That string is valid syntax in several version grammars and sorts below every
  real release, so a consumer asking whether the installed version is below the
  fixed version got **yes**, for every advisory ever filed against the package.

## [0.2.1] — 2026-08-21

Windows now sees Store apps and installed updates, both from the registry and
neither costing a file open, so they are in the default scan rather than behind
`--full-scan`.

### Added

- **Store and MSIX packages** are now inventoried, from the AppModel package
  repository. Read without opening a file, so this runs in the default scan
  rather than behind `--full-scan`. Resource bundles are filtered out — one
  ships per display scale and per language, and counting them turns a single
  application into a dozen rows differing only in an asset resolution — as are
  packages under `Windows\SystemApps`, which are the shell rather than
  installed software.
- **Installed Windows updates**, by KB number, from the component store. Not
  from `Win32_QuickFixEngineering`, which is what `Get-HotFix` reads: on a
  machine whose component store held 7,844 package entries, that class reported
  three updates. The store records one key per component per update, so KB
  numbers are deduplicated, and the component count behind each is kept.

### Changed

- **Operating-system components are out of scope by decision rather than by
  omission.** `C:\Windows\WinSxS` held 39,536 executables on a real machine —
  40% of every candidate on the volume — and they are hard-linked servicing
  copies that say little individually. The installed-updates list expresses the
  same thing in the form an operator patches by. The warning now says this
  instead of promising catalogers that were never going to be worth writing.

## [0.2.0] — 2026-08-21

Windows support, and a schema that carries who made a thing.

`swinv.exe` now collects an inventory rather than failing slowly at one. It is
**experimental**: one week old, exercised on CI and a single developer laptop,
with real gaps named in [docs/WINDOWS.md](docs/WINDOWS.md) — operating-system
components and Store apps are not inventoried, and per-user software is visible
only for the account running the scan. The Linux collector is unchanged in what
it finds; every cross-distro count still matches its own package manager
exactly.

### Added

- **Windows host identity.** `os_id`, `os_version_id`, `os_pretty_name`,
  `machine_id` and `kernel_release` are read from the registry, so a Windows
  report can be grouped and joined alongside Linux ones. `machine_id` comes
  from `MachineGuid` and is normalised to the same 32-hex-character shape as a
  Linux `machine-id`. Two traps are handled: the registry says "Windows 10 Pro"
  on Windows 11 hosts, and client and server share build numbers, so a server
  reports its release year rather than a client major.
- **A Windows binary in releases**, `swinv-<version>-windows-amd64.exe`,
  covered by the same `SHA256SUMS`. A binary only — no MSI, which would claim a
  maturity this does not have.

- **MFT enumeration for Windows** (`internal/usn`), the first piece of the
  Windows collector that is not the Linux one cross-compiled. It reads a record
  per file straight from the Master File Table via `FSCTL_ENUM_USN_DATA`,
  opening nothing. On a stock Windows 11 volume it read **1,301,728 records in
  42 seconds** and kept the **9.8%** that are executables — the other 90.2% cost
  one record each and are never touched, where a directory walk would have
  opened all 1.3 million. `C:\Program Files` alone, a fraction of that volume,
  does not finish inside ten minutes through the directory resolver. Not yet
  wired into the scan path.
- **A working Windows collector.** `swinv.exe` now produces a real inventory
  instead of running the Linux filesystem scan on a platform that keeps its
  records elsewhere. It reads the uninstall registry for installed products —
  fast, no elevation, no file opened — and with `--full-scan` enumerates the
  MFT, attributes each executable to a known product, and opens only what is
  left to read its PE version resource. `--volumes D:` or `D:,E:` selects which
  volumes to enumerate, replacing the default of `C:` rather than adding to it.
- **`Component.attributes`**, a string map for ecosystem-specific identity —
  Windows product codes, registry keys, install scopes, the several version
  strings a PE resource carries — and with it schema `1.3`. In JSON and
  CycloneDX properties, deliberately not in the CSV, whose fixed column shape
  is what lets files be concatenated across machines.
- **The Windows architecture is now measured rather than reasoned.** The
  proposed derived allowlist does not hold up — only 106 of 380 installed
  products record an `InstallLocation`, and adding `DisplayIcon` and
  `UninstallString` raises that to 147, covering 57.8% of third-party
  executables. What the measurement showed is that the allowlist was pointed
  the wrong way: enumeration is cheap (a 2.9-million-record volume in under
  five seconds, nothing opened) and *extraction* is what costs. A file under a
  known product's directory already has its version from the registry, so
  registry coverage is an extraction filter, not a scan filter. Applied that
  way it cuts files needing to be opened from 99,919 to 19,549 — 80% fewer.
- **The Windows uninstall registry reader** (`internal/arp`), which is the
  Windows equivalent of reading a package database: names, versions, publishers
  and install locations, with no file opened. It covers all three scopes —
  native `HKLM`, `WOW6432Node` for 32-bit installs, which are invisible to code
  that reads only the native key, and `HKCU`. Never via `Win32_Product`, whose
  enumeration triggers MSI repair and can modify the machine.
- **`--usn-probe` and `--volumes`**, Windows-only and experimental. The probe
  enumerates the MFT and reports what it found — record count, candidate count,
  timing, and where the candidates live — without scanning or opening anything,
  so the numbers that decide the rest of the Windows design come from real
  machines rather than from a hosted runner with nothing installed on it.
  `--volumes D:` or `--volumes D:,E:` **replaces** the default of `C:` rather
  than adding to it. Passing `--volumes` without `--usn-probe` is a usage error
  rather than being ignored, so nobody believes they have restricted a scan
  when they have not.
- **CI now runs natively on `windows-latest`**, which is elevated and NTFS —
  the two things MFT enumeration requires. `docs/WINDOWS.md` set a condition
  that no Windows work should begin without a machine to test on, and a hosted
  runner satisfies it.
- **`Component.vendor`**, the organisation behind a component, and with it
  schema `1.2`. It comes from whichever field the ecosystem uses — an rpm
  `Vendor`, a dpkg or apk `Maintainer`, a Python or npm `Author`, `Vendor` from
  a systemd ELF package note, or `CompanyName` from a Windows PE version
  resource, which is what makes a `.dll` attributable to its publisher. The raw
  value is kept rather than normalised, because a Debian maintainer and a
  Microsoft `CompanyName` are related but not identical facts. Additive: JSON
  omits it when empty, `vendor` is appended as CSV column 18 so positional
  readers are unaffected, and CycloneDX maps it to `publisher`. Present on 23%
  of components on a full Debian-family host — 66% of `deb`, 0% of kernel
  modules — so absence means "not recorded", not "no vendor".
- **swinv now gets out of the way of the machine it is inventorying.** By
  default a scan runs at `nice 10` with the idle I/O scheduling class on Linux,
  in background priority mode on Windows, and with a quarter of the CPUs as
  cataloger workers rather than all of them. An inventory collector is
  background maintenance — unattended, on a timer, on a machine doing real
  work — and a scan that finishes sooner but makes an interactive session
  stutter has made a bad trade. `--fast` restores the previous behaviour for
  when a person is waiting: measured on `/usr` on an 8-core host, the default
  takes 41.6 s against 30.6 s with `--fast`, so politeness costs about a third
  of the runtime. An explicit `--parallelism N` still overrides both.
- **`--debug-stacks-after DURATION`** writes every goroutine stack to a file
  while a scan is still running, for diagnosing one that appears to have hung.
  Go already does this on `SIGQUIT`, and on Windows on Ctrl+Break, but neither
  is reachable from a systemd timer or a Windows scheduled task, and many
  laptops have no Break key — which is exactly the situation the first Windows
  tester was in.
- **A long scan now says it is still alive**, every 30 seconds, with elapsed
  time, memory taken from the operating system, and the deadline. Memory is on
  the line because its growth is what distinguishes a scan that is merely slow
  from one that has started paging and dragged the whole machine down with it —
  a distinction that cost an afternoon of diagnosis when the heartbeat itself
  went silent for nine minutes on a Windows host. Between "scanning ..." and the result there was
  previously no output at all for up to 30 minutes, so a slow scan and a hung
  one were indistinguishable — which is exactly how the first Windows run was
  read, and reasonably so.

- `docs/SERVER-ROLES.md`, the proposed design for detecting what is running and
  serving — as distinct from what is installed — on both platforms, including
  IIS. Also unimplemented. Its measurements corrected three assumptions it was
  written to confirm: binary version banners cover far less than expected,
  deleted-mapping drift detection had a 100% false-positive rate unfiltered, and
  a container's service is misattributed to the host unless every path
  resolution goes through `/proc/PID/root`.
- `docs/WINDOWS.md`, the proposed design for Windows support, marked clearly as
  unimplemented, with a protocol for measuring the current binary on a real
  Windows machine.
- CI cross-compiles and vets `windows/amd64` on every push and publishes the
  binary as an artifact, so the portability the design assumes keeps being true.

- CI now runs the cross-distro comparison on every push, checking swinv's count
  against Alpine, Debian, Fedora, Arch and openSUSE's own package tooling, plus
  an arm64 smoke test under emulation. A Syft upgrade that stops reading one
  package database now fails the build instead of silently thinning
  inventories.

### Changed

- **`--output-mode` now defaults to `timestamped` rather than `dated`**, so
  reports are named `{hostname}-{datetime}` and every run is kept. Under
  `dated` a second run on the same day silently replaced the first, which meant
  an operator investigating what changed had one data point where they expected
  two. Files now accumulate and nothing prunes them; `--output-mode dated`
  restores the old behaviour, and the `{hostname}-latest.{ext}` pointer is
  unaffected either way.
- **`--help` was rewritten.** It was Go's stock `flag` output: 32 flags,
  alphabetical, ungrouped, 75 lines, one description 203 characters long that
  wrapped into mush on any normal terminal. It is now grouped by what an
  operator is trying to do, hard-wrapped at 78 columns, and opens by saying
  what a bare `swinv` will do to the machine. Examples, exit codes and pointers
  to the man page close it out. Each platform gets its own page: the Linux
  binary no longer lists `--usn-probe`, and the Windows one no longer describes
  `/home` and snaps.
- **`--help` prints to stdout and exits 0**, so `swinv --help | less` is no
  longer an empty pager. Usage errors still go to stderr, and no longer print
  the entire help page after the one line saying what was wrong.
- **Scan warnings are printed, not only recorded in the report.** Every
  warning — not running as root, unidentified files, filesystems skipped —
  went into the JSON where only someone who opened it would find them.

### Fixed

- **`ran_as_root` was always `false` on Windows, including for an elevated
  Administrator.** `os.Geteuid` returns a hard-coded `-1` there — not an error
  and not an unsupported marker — so the check reported "unprivileged" for a
  fully elevated process and put a confident wrong value in the report.
  Privilege is now detected per platform, via the process token's elevation
  flag on Windows, and the accompanying warning is phrased for the platform
  rather than telling a Windows operator they are "not running as root".
- **The missing-mount-table warning gave Linux advice on Windows.** A Windows
  run reported that it could not read `/proc/self/mountinfo`, which is true and
  useless. It now states the consequence an operator can act on: without
  drive-type filtering, network drives, removable media and cloud-sync folders
  under the scan root are walked like any local directory.

- **`--timeout` was not a whole-run deadline.** Syft indexes the filesystem with
  `filepath.Walk`, which takes no context and checks no cancellation, so a scan
  wedged in indexing never reaches a point where the deadline is consulted: a
  `--timeout 5m` run on a Windows host was observed still going at 5m30s with no
  sign of stopping. A watchdog now terminates the process ten seconds past the
  deadline. Atomic writes mean a terminated run can leave a `.tmp-*` file but
  never a half-written report.

- **Every write would have failed on Windows.** The atomic write path fsyncs
  the target directory after the rename, and Windows has no such operation:
  `FlushFileBuffers` rejects a directory handle with `ERROR_INVALID_FUNCTION`,
  which matched none of the three errors the code tolerated. Directory sync is
  now a documented no-op on Windows, where `MoveFileEx` journals the directory
  entry itself, and unchanged everywhere else. Found by reading the code before
  running it, which is not how the other bugs in this file were found.

### Verified

- **arm64 executed for the first time**, under QEMU emulation: apk 16/16,
  dpkg 78/78, rpm 147/147, with `host.architecture` correctly reporting
  `arm64`. Previously the binary was only ever cross-compiled and checksummed.

## [0.1.2] — 2026-08-19

### Fixed

- **A `--root` other than `/` got no exclusions at all**, so scanning a mounted
  root filesystem walked its `proc`, `sys` and every home directory on it. Found
  by running the container recipe from the README — `-v /:/host:ro --root /host`
  — which hung rather than completing. A tree containing `etc/os-release` is now
  recognised as a root filesystem and gets the usual layout exclusions, with a
  warning saying so. An arbitrary directory still gets none, which was the
  original intent.
- **Quotes Syft leaves in os-release values are stripped.** Gentoo writes
  `ID='gentoo'`, and the quotes arrived inside `host.os_id`, a CSV column and a
  fleet grouping key, so `WHERE os_id = 'gentoo'` matched nothing.

### Verified

- Each binary is now published twice, once with the version in its name and
  once without, so `releases/latest/download/swinv-linux-amd64` resolves for
  every release and install instructions never carry a version that goes stale.
- **Seven package managers checked against their own tooling**, each an exact
  match: Alpine apk 16/16, Debian dpkg 78/78, Fedora rpm 147/147 (257/257 on a
  real host), Arch pacman 137/137, openSUSE rpm 123/123, Gentoo portage
  296/296, Ubuntu dpkg 1,587 against 1,586 installed — correctly excluding 11
  packages removed with their config kept. The Alpine run also proves the
  `CGO_ENABLED=0` binary carries no glibc assumption.

- The CycloneDX handoff to `grype` was executed end to end for the first time.
  `grype` v0.117.0 accepted a 568-component document from a Fedora 44 host and
  returned 234 vulnerability matches across `rpm` and `go-module` components.
  Because CVE matching is a join on package identity, this also confirms the
  emitted PURLs are well-formed — the CycloneDX writer is built from
  `cyclonedx-go` rather than reusing Syft's encoder, so that was not a given.
- The Go module and binary catalogers ran against real Linux binaries on a
  non-Debian host.

## [0.1.1] — 2026-08-19

### Fixed

- **Host-shared filesystems were scanned, so another operating system's
  software was reported as installed on this one.** The non-local filesystem
  list covered network and virtual filesystems but not the ones a hypervisor
  or WSL uses to project the *host's* directories into a guest. On a Fedora 44
  guest under WSL2, `/usr/lib/wsl` is a `9p` mount carrying the Windows host's
  driver packages: 477 of that host's 1,003 components — 48% of the whole
  inventory — were ASUS, Intel and NVIDIA binaries and .NET assemblies
  reported as installed Linux software, with nothing marking them foreign.
  `9p`, `virtiofs`, `drvfs`, `lxfs`, `vboxsf`, `vmhgfs`, `prl_fs` and the
  network filesystems `ceph`, `glusterfs`, `lustre`, `beegfs`, `afs`, `smbfs`
  and the cloud-storage FUSE drivers are now excluded alongside the rest.

### Changed

- Documentation no longer uses `$(hostname)` in example commands. `hostname` is
  not installed on a minimal Fedora, in many container images, or on hardened
  builds, so those commands expanded to a path with nothing before
  `-latest.json` and failed confusingly. They use a glob instead, which needs
  no external command.

### Verified

- The rpm cataloger was exercised on a real Fedora 44 host for the first time
  and matched `rpm -qa` exactly: 254 found against 254 installed, nothing
  missed and nothing invented. This is the first confirmation that the
  pure-Go SQLite driver reads Fedora's `rpmdb.sqlite`, a code path no
  Debian-family host can reach.
- The `.rpm` package installs and runs on Fedora via `dnf install`.

## [0.1.0] — 2026-08-19

First public release.

### Added

- Scans a Linux host and enumerates installed software — OS packages
  (dpkg, rpm, apk, pacman, portage, nix, Homebrew, snap), roughly 40 language
  ecosystems, and loose binaries — by importing
  [Syft](https://github.com/anchore/syft) v1.51.0 as a library.
- Four output formats: JSON, CSV, NDJSON and CycloneDX 1.6, schema `1.1`.
- `--output-mode` chooses how files accumulate across runs: `dated` (one file
  per day), `overwrite` (one fixed file), or `timestamped` (a new file per run).
- `--since` produces a delta of added, removed and version-changed components
  against a previous report; `--delta-only` emits just the diff.
- `--hash` records a SHA-256 per component.
- `--offline` performs no network activity at all.
- `--skip-nested-rootfs` drops packages that came from a second root filesystem
  stored inside the scanned one.
- `--max-memory` sets a soft memory limit.
- Atomic writes: temp file, `fsync`, `rename`, then directory `fsync`, so a
  collector can never read a half-written inventory.
- `.deb` and `.rpm` packages for `linux/amd64` and `linux/arm64`, plus systemd
  service and timer units. The timer ships disabled.
- A CI licence gate that fails the build on any GPL, AGPL, LGPL or
  unidentified dependency.

### Known limitations

- Scanning `/` walks into any nested root filesystem on disk and reports its
  packages as installed, labelled with the host's distribution. `swinv` warns
  when it detects this; `--skip-nested-rootfs` removes them.
- Ubuntu/dpkg and Fedora/rpm on amd64 have been exercised on real hardware. The
  apk, pacman, portage and nix catalogers are wired in but untested on a real
  host of that family. The arm64 binary cross-compiles and has never been
  executed.
- A full scan takes minutes and peaks above 512 MB. The cost is Syft's
  whole-filesystem index; `--catalogers os` does not avoid it. Measured numbers
  are in `docs/PERFORMANCE.md`.

## Versioning

While `swinv` is `v0.x`, the CLI surface, the output schema and cataloger
coverage may change in any release; breaking changes are called out here.

The output document carries its own `schema_version`, currently `1.8`,
independent of the tool version. After `v1.0.0` the schema follows semver in
its own right: a minor bump is additive and safe for existing consumers, a
major bump is breaking.

[Unreleased]: https://github.com/chaugan/swinv/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/chaugan/swinv/releases/tag/v0.4.0
[0.3.0]: https://github.com/chaugan/swinv/releases/tag/v0.3.0
[0.2.3]: https://github.com/chaugan/swinv/releases/tag/v0.2.3
[0.2.2]: https://github.com/chaugan/swinv/releases/tag/v0.2.2
[0.2.1]: https://github.com/chaugan/swinv/releases/tag/v0.2.1
[0.2.0]: https://github.com/chaugan/swinv/releases/tag/v0.2.0
[0.1.2]: https://github.com/chaugan/swinv/releases/tag/v0.1.2
[0.1.1]: https://github.com/chaugan/swinv/releases/tag/v0.1.1
[0.1.0]: https://github.com/chaugan/swinv/releases/tag/v0.1.0
