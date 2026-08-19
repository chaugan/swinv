# Changelog

All notable changes to `swinv` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

`swinv` is `v0.x`: while the tool is tested and in use, the CLI, the output
schema and cataloger coverage may still change between releases. See
[Versioning](#versioning) below.

## [Unreleased]

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

## [0.1.0] — unreleased

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

[Unreleased]: https://github.com/chaugan/swinv/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/chaugan/swinv/releases/tag/v0.1.0
