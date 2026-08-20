# Changelog

All notable changes to `swinv` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

`swinv` is `v0.x`: while the tool is tested and in use, the CLI, the output
schema and cataloger coverage may still change between releases. See
[Versioning](#versioning) below.

## [Unreleased]

### Added

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
  time and the deadline. Between "scanning ..." and the result there was
  previously no output at all for up to 30 minutes, so a slow scan and a hung
  one were indistinguishable — which is exactly how the first Windows run was
  read, and reasonably so.

### Fixed

- **Every write would have failed on Windows.** The atomic write path fsyncs
  the target directory after the rename, and Windows has no such operation:
  `FlushFileBuffers` rejects a directory handle with `ERROR_INVALID_FUNCTION`,
  which matched none of the three errors the code tolerated. Directory sync is
  now a documented no-op on Windows, where `MoveFileEx` journals the directory
  entry itself, and unchanged everywhere else. Found by reading the code before
  running it, which is not how the other bugs in this file were found.

### Added

- `docs/WINDOWS.md`, the proposed design for Windows support, marked clearly as
  unimplemented, with a protocol for measuring the current binary on a real
  Windows machine.
- CI cross-compiles and vets `windows/amd64` on every push and publishes the
  binary as an artifact, so the portability the design assumes keeps being true.

### Verified

- **arm64 executed for the first time**, under QEMU emulation: apk 16/16,
  dpkg 78/78, rpm 147/147, with `host.architecture` correctly reporting
  `arm64`. Previously the binary was only ever cross-compiled and checksummed.

### Added

- CI now runs the cross-distro comparison on every push, checking swinv's count
  against Alpine, Debian, Fedora, Arch and openSUSE's own package tooling, plus
  an arm64 smoke test under emulation. A Syft upgrade that stops reading one
  package database now fails the build instead of silently thinning
  inventories.

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

The output document carries its own `schema_version`, currently `1.1`,
independent of the tool version. After `v1.0.0` the schema follows semver in
its own right: a minor bump is additive and safe for existing consumers, a
major bump is breaking.

[Unreleased]: https://github.com/chaugan/swinv/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/chaugan/swinv/releases/tag/v0.1.2
[0.1.1]: https://github.com/chaugan/swinv/releases/tag/v0.1.1
[0.1.0]: https://github.com/chaugan/swinv/releases/tag/v0.1.0
