# Contributing to `swinv`

How to build, test, and change `swinv` without breaking the things that were
hard to get right.
Part of the [swinv](README.md) documentation.

The specification of record is
[`docs/INVENTORYCOLLECTORSPEC.md`](docs/INVENTORYCOLLECTORSPEC.md). It describes
the system as built and measured, and it wins any disagreement with this
document. Read it before proposing a design change.

---

## Getting set up

Tagged releases publish static binaries and `.deb`/`.rpm` packages for
`linux/amd64` and `linux/arm64`. To work on `swinv` itself, build from source.

| Component | Pinned version | Why pinned |
|---|---|---|
| Go | **1.26.6** | Syft v1.51.0 declares `go >= 1.26.3` in its `go.mod` |
| `github.com/anchore/syft` | **v1.51.0** | Every behaviour note below is verified against this version |

Never use `@latest` for either. If your toolchain is older than 1.26.3 and
cannot auto-download a newer one, the build fails with an error that does not
look like a version problem at all:

```
unrecognized import path "golang.org/toolchain"
```

Install a current Go and try again.

On the development box Go lives outside the default `PATH`. The `Makefile`
prepends `/usr/local/go/bin` when it finds a `go` there, so `make` works without
help; a bare `go` command does not:

```sh
export PATH=/usr/local/go/bin:$PATH
```

### Make targets

```sh
make build          # bin/swinv, CGO_ENABLED=0, -trimpath, version/commit stamped
make test           # go test -race ./...
make lint           # go vet ./... , then golangci-lint if it is installed
make golden         # rebuild, then regenerate testdata/golden from testdata/rootfs
make bench          # wall time and peak RSS of a scan over testdata/rootfs
make licenses       # run license-check, then regenerate THIRD_PARTY_LICENSES.md
make license-check  # fail on any GPL/AGPL/LGPL/unknown dependency
make release        # linux/amd64 + linux/arm64 + dist/SHA256SUMS
make clean          # remove bin/, coverage output, and the bench output tree
```

`build` is the default goal. `VERSION` and `COMMIT` come from `git describe` and
`git rev-parse`, falling back to `dev` and `none` outside a checkout.

### Two optional tools

Neither is a module dependency, and neither is required to build.

- **`golangci-lint`** - `make lint` runs `go vet` unconditionally and then runs
  `golangci-lint` only if it is on `PATH`, printing a skip notice otherwise. CI
  always runs it, so a local skip is not a pass.

  ```sh
  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
  ```

- **`go-licenses`** - used by `make licenses` and `make license-check`. If it is
  not on `PATH` the `Makefile` falls back to
  `go run github.com/google/go-licenses@v1.6.0`, which re-downloads it on every
  invocation. Install it once to avoid that:

  ```sh
  go install github.com/google/go-licenses@v1.6.0
  ```

`make bench` prefers GNU `/usr/bin/time -v` for peak RSS and degrades to
wall-clock only when it is unavailable.

---

## The architectural rule

**`internal/scan` is the only package permitted to import Syft. Everything
downstream operates on `internal/model` types.**

This is the single rule that governs where new code goes. It buys two things:

1. A Syft API break is contained to one package. Syft is a large, fast-moving
   dependency; the blast radius of a version bump is `internal/scan` and nothing
   else.
2. A second collection backend can be added later without touching the writers,
   because the writers have never seen a Syft type.

The visible consequence, and the reason the rule is not free: **the CycloneDX
writer does not use Syft's encoder.** It builds its document from `model.Report`
via `github.com/CycloneDX/cyclonedx-go`. Reusing Syft's encoder would be less
code, and would drag Syft into `internal/output`, which is exactly what the rule
forbids. Do not "simplify" it back.

### Package map

| Package | Responsibility | Constraints |
|---|---|---|
| `cmd/swinv` | Flag parsing and validation, wiring, report assembly, exit codes | Thin. Stdlib `flag` only - no Cobra, no Viper |
| `internal/model` | Output types, `SchemaVersion`, dedup/merge, deterministic sort, delta computation | **Stdlib only.** No dependencies at all |
| `internal/hostfacts` | Machine identity: hostname, machine-id, DMI, kernel, NICs | Stdlib only. Reads kernel interfaces directly; **never** shells out to `hostnamectl`, `dmidecode`, `ip`, or `uname` |
| `internal/scan` | Syft integration: source construction, exclusions, symlink preflight, cataloging, conversion, `--hash` digests | The only package that may import Syft |
| `internal/output` | JSON, CSV, NDJSON, CycloneDX writers, atomic writes, `-latest` symlinks | Operates on `model.Report`. Must not import Syft |

---

## The Syft landmines

Each of these cost real debugging time. They are all still live in v1.51.0.

### 1. The `modernc.org/sqlite` blank import is load-bearing

```go
// internal/scan/scan.go
_ "modernc.org/sqlite"
```

Syft v1.51.0 no longer registers a SQLite driver itself - it requires the
*consumer* to do it, exactly as its own `cmd/syft/main.go` does. Without the
import, `CreateSBOM` does not merely skip RPM databases: it **fails outright**
with `sqlite driver is required for cataloging newer RPM databases`, **even on a
host with no RPM database at all**.

The driver is pure Go, so `CGO_ENABLED=0` and the static binary survive. The
import is commented as load-bearing in the source. **Do not remove it**, and do
not "tidy" it into an `//go:build` guard.

### 2. Syft rewrites the exclusion slice in place

`directorysource.getDirectoryExclusionFunctions` does
`exclusions[idx] = root + exclusion`, rewriting `./proc/**` into
`/abs/root/proc/**` **in the slice you handed it**. Passing our own slice
corrupted `ScanMeta.Excluded` through the shared backing array: the report showed
absolute paths that changed with the scan root, instead of the patterns the
operator configured.

Always pass a copy:

```go
excludes := append(append([]string(nil), opts.Excludes...), quarantined...)
```

Anything else you hand to a Syft config should be treated the same way until
proven otherwise.

### 3. One unreadable symlink aborts the entire scan

This is the most important behaviour in the codebase. Upstream:
[anchore/syft#3286](https://github.com/anchore/syft/issues/3286), still open.

When Syft's indexer meets a symlink it queues the link's **target** as an
*additional root* - `addSymlinkToIndex` returns the target unless `os.Stat`
reports `ENOENT`, so a *permission* error still queues it. Each additional root
is then resolved with `filepath.EvalSymlinks` **before any path-index visitor
runs**, and `indexAllRoots` treats a failure there as fatal to the whole scan.
Observed on a live host running unprivileged: **zero components** after a
five-minute scan, from one virtualenv symlink pointing into `/root`.

**Excluding the target does not help.** That was tested, not assumed -
`--exclude './root/**'` failed identically, because the fatal resolution happens
before exclusions are consulted.

`internal/scan/preflight.go` is the workaround: an lstat-only walk, run before
Syft is handed anything, that finds symlinks whose target cannot be resolved and
excludes **the links themselves**, so the indexer never queues the bad root.
Quarantined links are recorded in `ScanMeta.Excluded` and counted in
`ScanMeta.Warnings`. Remove the preflight only when upstream fixes #3286.

**The preflight's own matcher deliberately only honours `./`-anchored
patterns.** `*/` and `**/` patterns are ignored there, so those paths are still
walked by the preflight. That asymmetry is intentional and must be preserved:
`*/` and `**/` do not mean quite the same thing once re-anchored to an absolute
root, and a matcher that skipped slightly too much would let through exactly the
symlink the pass exists to catch - resurrecting the zero-component failure. Extra
`lstat` calls are cheap; a lost scan is not. If you touch `absoluteMatchers`, be
sure you are erring towards walking more, never less.

### 4. `sbom.Artifacts.LinuxDistribution` may be nil

It is a `*linux.Release` and it is nil more often than you would guess - a tree
with no `os-release`, or cataloging that failed early. Scanning `/usr/bin`
produces a nil distribution. Always nil-check, and fall back to
`internal/hostfacts`:

```go
if s == nil || s.Artifacts.LinuxDistribution == nil {
    return nil
}
```

---

## Testing expectations

Before you open a pull request:

```sh
make test   # go test -race ./...
make lint   # go vet ./... + golangci-lint
```

Both must be clean. CI runs the same gates plus the licence gate and a
systemd-unit check.

**The race detector needs cgo.** That applies to the test step only -
`CGO_ENABLED=1` for `go test -race`, while the shipped binary is always built
with `CGO_ENABLED=0`. CI sets it per step and then asserts with `ldd` that
`bin/swinv` is not a dynamic executable. Do not "fix" a race-detector build
failure by making the product binary dynamic.

Golden files live in `testdata/golden` and are generated from the fixture rootfs
in `testdata/rootfs`. Regenerate them with `make golden` (which sets
`SWINV_UPDATE_GOLDEN=1`) and **review the diff before committing** - a golden
update is a claim that the output change is intended.

### Tests that must not be weakened

Each of these encodes a bug that actually happened. Changing one to make a new
change pass is almost always the wrong fix.

| Test | The bug it encodes |
|---|---|
| `TestQuarantineSymlinks` | One unresolvable symlink aborting the scan - the zero-component failure behind the preflight |
| `TestSnapMountsSurviveTheSquashfsRule` | Snaps are squashfs loop mounts, so the "skip non-local filesystems" rule silently deleted the "scan snaps" rule and made `--no-snap` a no-op |
| `TestHashComponentsSkipsSharedEvidenceFiles` | Hashing `/var/lib/dpkg/status` gave every deb the same digest and made every package look changed whenever any one changed |
| `TestNormalizeIsOrderIndependent` | Dedup and merge must not depend on cataloger completion order; the output has to be byte-identical between runs |
| `TestLoadBaselineRejectsNonReports` | A `--delta-only` report used as a `--since` baseline reports every unchanged package as newly added |

### Linting

`.golangci.yml` runs the standard set plus `bodyclose`, `copyloopvar`,
`errorlint`, `gosec`, `nolintlint`, `revive`, and `unconvert`.

**`misspell` is deliberately disabled.** The codebase writes British prose in
comments and documentation ("behaviour", "licence") but must use the US
spellings baked into the Go and Syft APIs it calls (`cataloging`, `Artifacts`,
`Normalize`). No single misspell locale accepts both, so the linter produces only
false positives here. Do not enable it, and do not Americanise the prose to
satisfy it.

Follow the same split in your own contributions: British spelling in prose and
comments, US spelling wherever it is an identifier from an API we do not own.

---

## The licence gate

`swinv` is Apache-2.0 and **must stay free of GPL, AGPL, and LGPL code**.
Linking a GPL module into the binary would force the entire combined work under
the GPL. This is a hard requirement, not a preference.

`make license-check` fails the build if any dependency's licence is GPL, AGPL,
LGPL, or unidentified. CI runs it as its own job, then runs `make licenses` and
fails again if `THIRD_PARTY_LICENSES.md` is stale - so regenerate and commit that
file whenever the dependency graph changes.

### `licenses-allowlist.txt`

`go-licenses` classifies a dependency by pattern-matching its `LICENSE` file, and
two dependencies ship permissive licences in prose it cannot recognise:

| Module | Actual licence | Read where |
|---|---|---|
| `github.com/xi2/xz` | Public domain - the LICENSE says so in as many words | Module cache, `xi2/xz@v0.0.0-20171230120015-48954b6210f8/LICENSE` |
| `modernc.org/mathutil` | Verbatim 3-clause BSD text | Module cache, `modernc.org/mathutil@v1.7.1/LICENSE` |

Both were read by a human, and the allowlist records the licence found and where
it was read from. That is the entire purpose of the file: it exists to document
an audit, not to silence the gate.

**The hard rule: an allowlist entry only ever suppresses an "Unknown"
classification. It can never suppress a detected GPL/AGPL/LGPL.** The gate checks
for copyleft *before* it consults the allowlist and reports such a module as
`copyleft - NOT allowlistable` regardless of what is listed. This has been
negative-tested in both directions - injecting a GPL dependency correctly failed,
and flipping an allowlisted module to LGPL **also** correctly failed. Preserve
that property in any edit to the gate.

Adding an entry is only legitimate when you have opened the dependency's actual
`LICENSE` file, read it, and found it genuinely permissive. Record the licence
and the path you read it from, as the existing entries do.

**If you want functionality whose only implementation is GPL, stop and raise it
as a question.** Do not import it and do not vendor it.

---

## Adding a new output field

The formats do not all pick up a new field automatically. Work through this list.

1. **`internal/model/model.go`** - add the field to `Component` (or `Report`,
   `Host`, `ScanMeta`) with a `snake_case` JSON tag. Optional fields take
   `omitempty`.
2. **Dedup and ordering** - if the field takes part in identity, update
   `Component.identity`, `Component.key`, and `Less`. If it is merged across
   duplicates, extend `Normalize`: multi-valued fields union and sort,
   single-valued fields take the first non-empty value so the result does not
   depend on cataloger completion order.
3. **Populate it** - `componentFromPackage` in `internal/scan/scan.go` for
   anything derived from a Syft package; `internal/hostfacts` for host identity.
4. **`internal/output/csv.go`** - append the column to `csvColumns` and write it
   in `WriteCSV`. **CSV columns are unconditional**: they are emitted even when
   the flag that populates them was not used, so the column shape never varies
   with flags and files stay concatenable across machines and runs. Do not make a
   column conditional.
5. **`internal/output/ndjson.go`** - `ndjsonLine` is an explicit struct, so a new
   component field does **not** appear there for free. Add it if it belongs.
6. **`internal/output/cyclonedx.go`** - map it in `cdxComponent` or as a scan
   property, if CycloneDX has somewhere sensible to put it. Build it from
   `model.Report`; do not reach for Syft's encoder.
7. **`internal/output/json.go`** needs nothing: it marshals `model.Report`.
8. **Bump `SchemaVersion`** per the policy below.
9. **Tests** - extend the unit tests, then `make golden` and review the diff.
10. **Docs** - update the flag/format tables in `README.md` and §6 of the spec.

---

## Bumping Syft

1. Change the version in `go.mod` to an exact tag. Never `@latest`.
2. Check the new `go.mod` for a raised Go requirement. If it moved, update the
   pinned Go version in `README.md`, the spec, and `GO_VERSION` in
   `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
3. Re-verify the integration against upstream sources: `syft/create_sbom.go`,
   `syft/get_source.go`, `syft/create_sbom_config.go`, and `syft/cataloging/`.
   The config builder in `internal/scan/scan.go` calls into all of them.
4. Re-check every landmine above. In particular: does Syft register a SQLite
   driver itself yet, does it still mutate the exclusion slice, and is
   [#3286](https://github.com/anchore/syft/issues/3286) fixed? If #3286 is fixed,
   the preflight can go - with its tests replaced, not merely deleted.
5. `make test` and `make lint`.
6. `make golden` and read the diff. A cataloger change upstream shows up here
   first.
7. `make licenses` - a Syft bump moves a large part of the dependency graph, and
   the licence gate is the thing that catches a new copyleft transitive.
8. Run the binary against a real host and sanity-check the component count and
   the licence coverage before and after.
9. `ScanMeta`/`Tool.SyftVersion` needs no edit: `SyftVersion()` reads the version
   out of `debug.ReadBuildInfo()`, honouring a `replace` directive.

---

## Schema versioning policy

`model.SchemaVersion` is a `MAJOR.MINOR` string.

| Change | Bump |
|---|---|
| A new optional field, omitted when unused | **Minor** |
| A new CSV column appended at the end | **Minor** |
| Renaming or removing a field or column | **Major** |
| Reordering CSV columns, or changing a field's type or meaning | **Major** |

The test is whether a consumer written against the previous version still parses
the document. `1.0 → 1.1` added `Component.SHA256` and `Report.Delta`; both are
additive and omitted when unused, so a 1.0 consumer still parses a 1.1 document.

A major bump is a real event: say so in the pull request, and update the spec's
§6 in the same change.

Note that `--since` deliberately accepts **any** schema version as a baseline.
Refusing an older report would break the flag exactly when it is most wanted -
immediately after an upgrade.

---

## Commits and pull requests

Keep both brief.

- One logical change per commit. Conventional-commit style subjects
  (`fix: quarantine symlinks before source construction`) are welcome but not
  enforced.
- Explain **why** in the body, not what - the diff already says what. The
  non-obvious reasons are the ones worth writing down, and several of them ended
  up in the spec as a result.
- A pull request should say what changed, why, and what you ran. `make test`,
  `make lint`, and `make license-check` at minimum; add `make golden` output if
  the golden files moved.
- If you changed a documented behaviour, update `README.md` and the spec in the
  same pull request. The spec is the specification of record - leaving it stale
  is a defect.
- If a change touches one of the tests listed above, say so explicitly and
  explain why weakening it is safe. The default answer is that it is not.

There is no CLA, no code of conduct file, and no formal governance model. If a
decision looks like it should be permanent, propose it as a spec edit so the
reasoning survives.
