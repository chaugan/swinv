# Changelog

All notable changes to `swinv` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

As of `v1.0.0`, `swinv` is stable: the CLI surface and the output schema follow
[semantic versioning](#versioning), and a breaking change waits for a new major
version. See [Versioning](#versioning) below.

## [1.0.1] - 2026-08-30

Close two ordering gaps in the v1.0.0 Windows output-directory hardening (R1):
the protection was real but could be silently bypassed by who created the
directory first.

### Security

- **The output directory is now secured before the scan starts, before
  anything writes under `--out`.** The v1.0.0 guard (`secureOutputDir` on
  Windows: an explicit SYSTEM/Administrators-only DACL on create, an owner
  check on an existing directory) ran inside `writeFiles`, late and on one
  path only. Two gaps followed from that ordering, both fixed by moving the
  guard to `ensureOutputDir`, called once in `run` before the scan:
  - **`--heartbeat` could void the protected DACL (high).** The heartbeat
    state writer created a missing `--out` with a plain `MkdirAll`, which on
    Windows produces a directory with the parent's inherited ACLs - on the
    default `C:\var\lib\swinv`, readable by every local user - and whose
    SYSTEM owner then passed the later owner check. On the first run into a
    fresh directory, the reports, the transmit spool (full scan payload) and
    the heartbeat state all landed in that permissive tree; an attacker who
    had pre-created the directory instead got SYSTEM to write the heartbeat
    state into it before the run aborted. The writer no longer creates the
    directory at all: the guard is the only thing that makes `--out`, and a
    missing directory degrades to the existing scan warning (one redundant
    full send next run), never to a silently unprotected write.
  - **`--stdout --transmit` bypassed the check entirely (medium).**
    `secureOutputDir` was only reachable through `writeFiles`, which a
    `--stdout` run skips - so the spool directory (`--out/spool`) was created
    by plain `MkdirAll` under an unvetted path, with the "forced 0600/0700"
    inert on Windows as everywhere POSIX modes meet ACLs. The guard now runs
    whenever anything pulls `--out` in: file output, `--heartbeat`,
    `--transmit`, or the `--debug-stacks-after` goroutine dump, which lands
    in `--out` mid-scan and was itself a bypass on a `--stdout` run. A pure
    `--stdout` run that writes nothing still creates no directory, and the
    send-only modes (`--transmit-check`, `--transmit-only`, `--transmit-from`)
    are unaffected.
  - The guard also creates missing **parent** directories before securing the
    leaf, so the default nested path works on a machine where `C:\var` does
    not exist; previously that failed outright unless the parents were made
    by hand - or by an attacker, which was the scenario R1 guarded against.
  Both fixes carry regression tests (the guard's condition table, creation
  and failure paths, and the heartbeat writer's refusal to create the
  directory), and SECURITY.md's R1 entry documents the strengthened
  guarantee.

## [1.0.0] - 2026-08-30

First stable release. The CLI and the output schema are now under semver, and
this release adds an HTML report for reading a single host's inventory by eye.

### Added

- **`--html-report PATH` writes a single self-contained HTML report**:
  distribution charts, drill-down tables, collapsible sections, and - on every
  data segment - the flag that produced it. It is offline by construction: the
  CSS and JavaScript are embedded, the charts are inline SVG, the data rides in
  one `<script type="application/json">` blob, and nothing is fetched. It rides
  alongside the machine-readable formats and is never the only output, so a
  failure to write it cannot discard the inventory already on disk.
- The report opens with **the command that produced the data** - the exact
  invocation the scan was run with, shown verbatim with the program name
  normalised to `swinv`. This is recorded in the report as `scan.profile.args`
  (schema `1.18`). A report written before that field existed, or one rebuilt
  with `--report-from` from such a file, falls back to a reconstruction from the
  scan profile's scope fields - which shows the non-default scope flags but
  cannot recover `--offline`, `--heartbeat` or the output paths.
- **`--report-from PATH` renders the report from an existing `json` or `ndjson`
  file** instead of scanning, so a collected inventory becomes a page without
  touching the host again. The format is detected automatically; NDJSON is
  reconstructed record by record and reflects what the stream carried. Requires
  `--html-report`.

### Changed

- **Declared stability.** The versioning language is now a commitment rather
  than a caveat: after `v1.0.0` the CLI and the output schema follow semver,
  and breaking changes are reserved for a major bump.
- **Schema `1.18`** adds `scan.profile.args`, the invocation the scan was run
  with. Additive and omitted when absent; swinv has no flag that carries a
  secret on the command line, so it exposes nothing a report does not already
  carry.

## [0.9.7] - 2026-08-29

Close two authorized_keys gaps an independent GLM review found in the v0.9.5
hardening.

### Security

- **Closed two gaps in the v0.9.5 local-attacker hardening**, found by an
  independent GLM review of the fix itself. The `authorized_keys` reader
  refused a bare FIFO but a *symlink to* a FIFO slipped past the Lstat gate
  and blocked the root process inside `open(2)` - the reads now open
  `O_NONBLOCK` and fstat the descriptor, so no symlinked FIFO or device can
  hang the scan. And the ownership gate exempted root-owned files, which let
  a symlink at `~/.ssh/authorized_keys` pointing to `/root/.aws/credentials`
  through - a file reached via symlink must now be owned by the account
  itself, while a genuine root-owned key file (StrictModes) is still read.
  Both cases are now regression-tested.

## [0.9.6] - 2026-08-28

Rename the component `source` field so it stops colliding with Splunk.

### Changed

- **The component `source` field is renamed `source_key`** (#16), schema
  `1.17`. Splunk reserves `source` as index-time metadata (the file path an
  event came from), so a component carrying its own `source` produced a
  silently multivalued field - correct totals with one value that is not a
  source. `source_key` is the same value under a name Splunk has not taken,
  the same reason this field is `hostname` and not Splunk's reserved `host`.
  The field is two releases old (1.16) with one known consumer, so renaming
  now costs least. JSON/NDJSON key, CSV column 21 and the CycloneDX property
  all change to `source_key`.

## [0.9.5] - 2026-08-28

Harden the privileged collector against unprivileged local users, and stop an
installer on disk being catalogued as the software it wraps.

### Fixed

- **A Windows installer or launcher on disk no longer enters the inventory as
  the software it wraps.** An executable's version resource can carry an
  application's ProductName but a different thing's version: `Firefox
  Installer.exe` read as `Firefox 18.05` (the 7-Zip self-extractor Mozilla
  wraps its installer in), and `Firefox.exe` on a Desktop with
  `original_filename: desktop-launcher.exe` read as Firefox 149 (a launcher
  shim). Either would raise findings for software not installed at that
  version. The row is kept (the file is present) and marked
  `attributes.role = "installer"` or `"launcher"` with `role_evidence`
  naming what decided it - an installer word in the description or original
  filename, a self-extractor stub (`7zS.sfx.exe`), an installer file name,
  or a curated launcher stub name - all from fields swinv already reads.
  Conservative by design to protect the standalone case: a portable single
  exe with no installer keeps its own name in `original_filename` and is
  never flagged, because a false positive would hide a real installation.

### Security

swinv runs as root or SYSTEM. A structured local-attacker review (nine root
causes, each adversarially verified, documented in [SECURITY.md](SECURITY.md))
drove the fixes below. Every one changes how swinv reads and writes, not what
it reports: a before/after scan of a reference host produced byte-identical
configuration records, the only intended output change being a single
canonicalized ELF link path.

- **`authorized_keys` and every config file are read safely.** A regular-file
  gate plus size cap, and an ownership gate on `authorized_keys`, so a symlink
  to `/dev/zero` (root OOM), a FIFO (hang), or `/root/.aws/credentials`
  (disclosure) planted in an attacker-owned home is refused rather than read
  by the root process.
- **`--no-service-command` now covers what it should.** Sudo NOPASSWD/broad
  evidence, ssh-key comments, and the Windows IFEO debugger line ride the same
  redaction switch as every other command line; they were not gated before.
- **Windows: the output directory is admin-only.** It is created with a DACL
  granting only SYSTEM and Administrators, and swinv refuses an existing
  `--out` owned by a non-admin - closing SYSTEM writing root inventory into a
  directory an unprivileged user pre-seeded, and the spool/heartbeat forgery
  that followed.
- **Secrets and the spool are owner-only.** The transmit spool is forced
  0600/0700 regardless of `--perm`; credential files (token, passphrase) open
  `O_NOFOLLOW` and are fstat-checked for owner and mode on the descriptor,
  closing the symlink-follow, ownership gap and stat/read race together.
- **The goroutine dump cannot be hijacked.** Written `O_EXCL|O_NOFOLLOW`, with
  an unpredictable `CreateTemp` fallback, instead of a predictable name in the
  shared temp directory.
- **The ELF probe cannot be pointed at arbitrary host files.** Resolved paths
  are cleaned, and a slash-bearing `DT_NEEDED` (never a real soname) is
  rejected, so a crafted listening binary cannot make the root probe stat or
  read files outside the library search.
- **The SUID walk cannot be inflated.** The number of recorded setuid entries
  is capped, and under `--config-scope all` a setuid file owned by a non-root
  user - which an attacker can mass-create and which grants no privilege - is
  skipped.

## [0.9.4] - 2026-08-28

Tell a narrower scan apart from an uninstall.

### Added

- **A narrower scan is no longer indistinguishable from software being
  uninstalled** (#15), schema `1.16`:
  - Every component carries `source`, the manifest `sources` key it is
    counted under (`dpkg`, not `dpkg-db-cataloger`). `found_by` and the
    sources vocabulary did not map by any rule a consumer could reproduce;
    now a component joins to the source that produced it directly, in JSON,
    NDJSON, the CSV (column 21) and CycloneDX.
  - The heartbeat carries `scan_profile` - `full_scan`, `hash`, `elf_scope`,
    `config_scope`, `ndjson_include`, `containers`, `services`, `root` -
    so a consumer compares two scans of a host only when they are
    comparable. A scan without `--full-scan` finds fewer components on
    purpose; treating that as remediation closed 5,331 findings downstream
    for files still on disk. With these two fields a finding can be closed
    when the source that produced its component ran and held when it did
    not - per finding, not a blanket per-host freeze.

## [0.9.3] - 2026-08-28

More of the persistence and privilege surface, collected.

### Added

- **The configuration surface's second slice** (#13): more of the persistence
  and privilege mechanisms, all local reads, each row carrying its ATT&CK
  technique and the owning package of the executable it names.
  - Linux: sudo rules (`T1548.003`, with NOPASSWD and broad-grant flagged),
    SSH `authorized_keys` per account (`T1098.004`), accounts from
    `/etc/passwd` - uid 0 and login-capable only (`T1078`/`T1136`), loaded
    and configured kernel modules (`T1547.006`), `/etc/ld.so.preload`
    (`T1574.006`), and system shell init under `/etc/profile.d`
    (`T1546.004`).
  - Windows: **Defender exclusions** (`T1562.001` - paths, extensions and
    processes; an exclusion over a writable directory is invisible to every
    version scanner), the services registry (`T1543.003`, ImagePath joined
    to its product), Image File Execution Options debuggers (`T1546.012`,
    only the hijacked entries), and AppInit_DLLs (`T1546.010`).
  New `config` record kinds: `sudo-rule`, `ssh-authorized-key`, `account`,
  `kernel-module`, `preload`, `shell-init`, `service`, `ifeo`, `appinit`,
  `av-exclusion`. All under the existing `--config-scope` and
  `--ndjson-include config`; `--no-service-command` redacts the command
  lines here too.

## [0.9.2] - 2026-08-28

Match a Windows host to Microsoft's own patch data.

### Added

- **The Windows patch-level join key**, schema `1.15` (#14): `os_build`
  ("10.0.26200.9168" - what the host itself reports, the build MSRC keys
  remediations on), `os_display_version` ("25H2", which decides
  end-of-service; the cumulative update's component version cannot tell
  24H2 from 25H2 because an enablement package keeps the older servicing
  branch), `os_edition` and `os_installation_type` (client and server
  share build branches whose update ranges sit ~24,000 revisions apart).
  On `host` in the JSON and on the heartbeat line - the one line a
  consumer always gets - read from
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` without
  elevation, `ReleaseId` fallback for pre-20H2 Windows 10. A build number
  is the one Windows assessment that does not have to infer.

## [0.9.1] - 2026-08-28

What v0.9.0 promised, delivered politely. Ten development builds were run and
measured on a real laptop (i7-12700H, 20 logical processors, Defender on) by
the operator who reported each defect; every fix below cites what was seen.

### Fixed

- **The Windows all-scope probe could burn twenty minutes and then vanish
  without a trace.** Three causes, all found by the first real run on a
  laptop: the probe shared the scan's --timeout context, which was already
  nearly spent, so every loop quietly obeyed the expired deadline and the
  output carried link: 0 with no error anywhere; the probe list included
  ~50,000 System32 DLLs the inventory's own rule says to represent by the
  installed updates, not file by file; and it ran unpaced at quarter-CPU,
  which turned the antivirus - which scans every open at its own priority -
  into a foreground workload ("almost killing the computer"). Now: the
  probe gets its own deadline (the transmitDeadline precedent), OS and
  Store territory is excluded from the probe list (system DLLs still
  appear as links, marked os_component, when something loads them), each
  worker pauses as long as its last parse took unless --fast, progress is
  logged every 30 seconds, and a deadline hit lands in scan.warnings as
  "the link records are PARTIAL" instead of silence.
- **A registry product with a recovered location under C:\Windows owned
  the operating system.** The "Application Compatibility Fix Database"
  entry's longest-prefix match claimed ntdll.dll, WS2_32.dll and
  wininit.exe on a real machine, and os_component never fired because the
  wrong owner answered first. The OS-territory check now outranks the
  containing-directory rung in both attribution ladders; only a component
  that recorded the exact file path may claim a file inside the Windows
  directory.
- **A zero-link probe result is a stated finding, not a silence**: the
  probe reports files probed, PE-parsed and linked, plus the first parse
  error verbatim, into the log and scan.warnings.

- **"Almost killing the computer it is running on."** The probe and the
  phases around it were rebuilt for politeness, verified fix-by-fix by an
  independent audit with the race detector on:
  - background mode now clamps the Go runtime - garbage collector included -
    to a quarter of the machine for the entire run, on every platform;
    `--fast` lifts it;
  - each probe worker pauses as long as its last parse took, with no side
    door: the pause lives next to the parse, so the sequential phase pays
    it too;
  - the owner-attribution ladder walked from O(links x locations) - billions
    of iterations and tens of gigabytes of garbage per run, the measured
    source of all-core GC bursts - to O(path depth) map lookups with
    memoization;
  - resolution stats, the OS-root string, and record counts are computed
    once instead of per call, and the big record slice is sized exactly;
  - a deadline hit now delivers everything parsed so far - a run that
    probed 42,411 of 46,325 files used to report zero.
  Measured across the builds: 89% CPU unpaced, 73% paced, **26% with the
  full stack**, and the post-probe write phase went from minutes of
  synchronized all-core bursts to seconds.
- **A registry InstallLocation ending in a separator never matched** the
  containing-directory rung, so products recorded as `C:\App\` silently
  lost attribution. Trailing separators are trimmed at indexing.
- The Linux ELF walk no longer runs on Windows, where "probing 0 binaries
  under /" explained itself poorly.

### Changed

- **All-scope Windows link records keep the signal and drop the OS graph.**
  The transitive walk pulled the whole operating-system DLL graph plus the
  virtual `api-ms-*` API sets into every binary's record set: 5,053,397
  link records and 1.8GB of NDJSON on the machine that measured it, nearly
  all of it saying "loads the operating system" - which the inventory
  already represents by the installed updates. At `--elf-scope all`,
  OS-component links (API sets included, now marked as such) are not
  recorded; product, vendored and unowned libraries are. Listening
  services keep their complete link sets, OS and all - a few dozen
  binaries ranked first deserve full fidelity.

- **The heartbeat digest includes `sha256` when `--hash` recorded one.** A
  binary replaced in place under the same version string was invisible to
  the identity-only digest, so the heartbeat suppressed the re-probed link
  records as "unchanged" - for up to `--full-interval` (24h default). With
  content in the digest, an in-place swap streams immediately. Toggling
  `--hash` itself now costs one full resend, which a timer never does. The
  digest was always documented as opaque and unstable across versions;
  upgrading causes one full resend per host, as any digest change does.

The measured end state on the reporting laptop, full bells
(`--full-scan --hash --config-scope all --elf-scope all --elf-symbols`,
background mode): 46,331 files probed in ~21 minutes at ~26% CPU, 77,507
link records in a 156MB NDJSON (down from 5,053,397 records and 1.8GB), and
an unchanged-heartbeat rerun writing 116KB. Among the first findings: three
generations of OpenSSL loaded side by side - 3.4.0, 3.0.16 and the
end-of-life 1.1.1g - plus vendored copies inside an MQTT broker and two
Siemens OT tools, and 9,986 links against a 2011-era Qt 4.8.0. No package
manager on Windows can produce that table.

## [0.9.0] - 2026-08-27

The import table: what every Windows binary loads.

### Added

- **PE import table reading on Windows**, schema `1.14`: the Windows sibling
  of the ELF linkage. Each listening executable's import table names the
  DLLs it loads and the functions it imports from each, resolved the way
  the loader searches - the importing object's directory, the application's
  directory (the order that makes DLL planting a technique), then System32
  or SysWOW64 by the binary's machine type - and joined to the products the
  inventory identified, `Name@Version` where no PURL exists, the services
  convention. New `os_component` on link records keeps System32 DLLs from
  reading as "nothing installed owns it". API sets carry no path by design;
  PATH and SxS resolution are not attempted - a miss is an empty path,
  never a guess. LoadLibrary and delay-loaded imports are the Windows
  dlopen, invisible to the import table and said so in the evidence.
  `--elf-scope` and `--elf-symbols` now appear on the Windows help page and
  do what they say there. `--elf-scope all` probes **every executable file
  the MFT enumeration saw** - the full-scope equivalent of the Linux ELF
  walk, riding the index `--full-scan` already builds instead of walking
  the filesystem twice, with one shared parse cache so the machine's
  ten-thousand imports of kernel32.dll cost one open. Without `--full-scan`
  it degrades to `listening` and says so. Proved against real import
  tables: the tests cross-compile a PE and read kernel32.dll's actual
  imports rather than a synthetic.

### Fixed

- **The SUID and ELF walks now honour `./`-anchored `--exclude` patterns**,
  the same subset the symlink preflight honours. They previously ignored
  excludes entirely, which stopped being theoretical when a CI runner's
  `/opt` toolchain cache cost the SUID walk six minutes of lstat calls
  while the command line said `--exclude './opt/**'` the whole time.

### Changed

- The MFT walk's log line names what it keeps (exe, dll, sys, ocx, cpl,
  drv): an operator read "114287 executables" and reasonably concluded the
  walk was exe-only, when DLLs are most of what it finds.

## [0.8.0] - 2026-08-27

What the machine is configured to run, and a transmit path fit for a real estate.

### Added

- **The configuration surface**, schema `1.13` (#13, first slice): the
  persistence and privilege mechanisms MITRE ATT&CK is largely made of, all
  collected as local reads. Linux: cron (system, cron.d, periodic
  directories, per-user spools), systemd timers and services (/etc shadowing
  /run shadowing /usr/lib), SUID/SGID binaries. Windows: Scheduled Tasks
  (task-store XML read directly, UTF-16 and all) and Run/RunOnce plus the
  Startup folder. Each entry names the executable it runs, joined to its
  owning package through the same probe the listening services use, the
  user and schedule where stated, whether the executable is world-writable,
  and the ATT&CK technique the mechanism is the surface for. New
  `config_surface[]` report section, `record_type: "config"` under
  `--ndjson-include config`, and `--config-scope standard|all|off`.
  `--no-service-command` redacts the command lines here too. A cron job is
  not a finding; a root cron job whose script is world-writable, or a SUID
  binary no package owns, is a join away.

- **Transmit mode grew its deployment surface** (#9), the flags an estate
  with real certificate handling and real network policy needs:
  - `--transmit-key` now accepts PKCS#8 encrypted private keys (PBES2, the
    format `openssl pkcs8 -topk8 -v2 aes-256-cbc` writes), decrypted
    in-process with no dependency added. The passphrase comes from a systemd
    credential (`swinv.key-passphrase`, TPM-sealed via
    `LoadCredentialEncrypted=`), `--transmit-key-passphrase-file` (refused
    unless mode 0600), or `$SWINV_TRANSMIT_KEY_PASSPHRASE`, in that order,
    each logged when used. The legacy RFC 1423 format is refused with the
    command that re-wraps it. No interactive prompt: this runs from a timer.
  - `--transmit-pin` verifies the server by public key (base64 SHA-256 of
    the SubjectPublicKeyInfo; repeatable for rotation), for the site whose
    CA cannot reach the trust store and should not be pushed to
    `--transmit-insecure`. A mismatch prints the pins the server presented.
  - `--transmit-check` validates endpoint, auth, TLS, certificate expiry,
    proxy and clock skew in one command, one greppable line per check,
    without scanning - so a bad token no longer takes a 30-minute scan to
    diagnose.
  - `--transmit-only` flushes the spooled backlog without scanning;
    `--transmit-from` sends an existing NDJSON file (relay hosts, backfill),
    refused when its manifest disagrees with its contents.
  - `--transmit-require-complete` (on by default) withholds the upload when
    an inventory source failed: a partial inventory on the server reads as a
    healthy small host, and the refusal belongs where the exit code is
    visible.
  - `--transmit-tls-min` (1.2 default, can only be raised),
    `--transmit-compress auto|always|never`, and `--transmit-rate-limit`
    for metered links.

### Fixed

- **Two ownership-probe misses, found the first time config entries were
  joined on a real host.** A file asked about under two spellings
  (`/bin/mount` from a snapd unit, `/usr/bin/mount` from the SUID walk)
  answered only the later asker, so mount reported as an unowned SUID binary
  on a host where the mount package plainly owns it - the probe map now
  keeps every spelling. And a probed path that is a symlink could never
  match dpkg's md5sums, which cannot list symlinks; Ubuntu's coreutils
  transition makes `/usr/bin/rm` exactly that, so the probe now also asks
  about the file the link resolves to, chased inside the scan root. Both
  fixes sharpen service attribution too, not only config records.

- **Pin verification runs in `VerifyConnection`, not
  `VerifyPeerCertificate`** - a resumed TLS session skips the latter, and a
  pinned connection must not be resumable past its pin. Caught by gosec
  before it shipped anywhere.

## [0.7.1] - 2026-08-25

Records that say where they belong, and a manifest that cannot be silently short.

### Added

- **`root` on exposure and link NDJSON records**, schema `1.12` (#11). The
  vocabulary is the one component records already use: `/` for the host, a
  nested root such as `/snap/core20/2866`, or `container:<short id>`. A snap
  base's libcrypto and the host's agree on every name and differ on every
  version; without this field a consumer joining on `(hostname, package)`
  attributes one install's library load to the other's inventory row. On a
  link record `root` names the install the library belongs to; on an exposure
  record, the install of the executable behind the port. `container_id` stays
  for compatibility, but `root` is the join key that also covers snaps and
  unpacked images.

### Fixed

- **The NDJSON manifest never declared link records, and the reconciliation
  could not notice** (#10). `--ndjson-include links` wrote link records the
  manifest did not count, and the writer-side check iterated the planned
  counts only - so a receiver dropping every link record reconciled clean:
  zero of zero declared arrived. The manifest now counts link records with
  the same suppression rule the writer uses, reconciliation fails on any
  record type written but never declared, and a test pins the invariant for
  the next record type. Losing link records is the quiet kind of loss: it
  reads as "no service loads the vulnerable library", which is reassuring
  rather than alarming.

## [0.7.0] - 2026-08-25

The transmit path, and what every binary actually loads.

### Added

- **Shared-library linkage**, schema `1.11`. Every ELF binary already carries
  a database of its own dependencies - the `DT_NEEDED` entries and the dynamic
  symbol table - and swinv now reads both without executing anything and joins
  each library to the package that owns it. `sshd` listening on `0.0.0.0:22`
  links `libcrypto.so.3` from `libssl3t64@3.5.5` and imports 120 of its
  functions: a CVE in a common library can be ranked by which network-facing
  services actually load it, instead of flagging every machine that merely has
  it on disk.

  Resolution follows `ld.so` without running it, chases ldconfig's symlinks to
  the file a package actually ships, and stays jailed inside the probed
  filesystem - a container's links resolve against its own musl and apk
  packages, never the host's glibc. Measured: 144 of 144 libraries across
  every listening service on the development host resolved to an owning
  package.

  `--elf-scope` picks the population: `listening` (default, adds nothing
  measurable to a scan), `all` (every ELF under the standard binary
  directories; 5,845 binaries, +6s warm and +66s cold on the development
  host), `off`. `--elf-symbols` adds the imported symbol lists, capped and
  marked as supporting evidence: most CVEs live in internal functions that
  appear in no import table, so "loads the library" is the reliable signal,
  and `dlopen` is invisible by construction with the evidence saying so.

  Output: `links` on services and container services, a `Report.links` table
  under `--elf-scope all`, `soname=purl` pairs in services CSV column 21,
  CycloneDX dependency edges from each service to its libraries' packages, and
  a `link` NDJSON record via `--ndjson-include links`. With `--heartbeat`,
  link records are suppressed on unchanged scans: they derive from installed
  software, which is exactly what the digest tracks, and repeating 36,000 rows
  hourly would undo the heartbeat.

- **`--transmit`**, an HTTPS destination alongside the files. swinv POSTs the
  scan it already writes to one endpoint: `POST /api/v1/ingest/scan` with the
  manifest, numbered NDJSON batches, then a close whose reconciliation verdict
  the collector checks.

  **File output stays first class.** `--transmit` adds a destination, it does
  not replace one. Air-gapped sites are the likeliest audience for this and
  they move files by means they already trust.

  Batched by line count **and** byte size, whichever trips first, because line
  count alone is not enough: a host with large attribute maps puts 2,000 lines
  well past any sane request body. Bodies are gzipped, roughly 9:1 on this
  data, which saves nothing on wall clock and a great deal on a metered link.

  **Idempotent and resumable.** Every scan gets a `scan_id`, sent with every
  batch, so a retry after a timeout cannot double-count a host. The NDJSON is
  spooled to `<out>/.swinv-spool/` before the first request and removed only
  once the server has accepted and reconciled it, so a collector that dies at
  batch nine is finished by the next run rather than rescanning, and a server
  that restarts mid-scan costs a few duplicate batches rather than the whole
  upload. The resume point comes from `GET .../status`: the server is the only
  party that knows what it stored. The batch boundaries are recorded in the
  spool, so changing `--transmit-batch-lines` between runs cannot shift what
  batch seven means.

  **Bearer token and client certificate, both.** Some estates will not
  distribute tokens; some cannot run an internal CA. There is deliberately no
  `--transmit-token` flag: every process on the machine can read
  `/proc/<pid>/cmdline`. `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` are
  honoured. Retries are bounded, exponential, and jittered, because a fleet on
  one systemd timer otherwise retries in lockstep. 5xx and network failures
  retry; 4xx do not, except `429`, which is the one 4xx that says "later"
  rather than "no".

- **A self-describing scan manifest**, schema `2` on the heartbeat record. It
  now states what the stream it heads actually contains: `scan_id`,
  `swinv_version`, `duration_ms`, `counts` by record type, and `sources` -
  one entry per enumeration source with `ok`/`skipped`/`error` and a reason.

  This is the feature that would have prevented an entire day of debugging. A
  host whose collector wrote 3,993 components once arrived as 15, and the
  forwarder, the indexer, the matcher and the dashboard all reported success,
  because nothing anywhere compared what arrived against what was sent. The
  matcher was right that fifteen packages contain no vulnerabilities.

  `counts.component` describes the stream and `n_components` describes the
  host; they differ only when `--heartbeat` suppressed the components, and the
  record then carries `inventory_unchanged` and `inventory_components` so a
  receiver reconciles against the right one. `n_components` keeps its exact
  previous meaning, so a server that predates this reads the record unchanged.
  The NDJSON writer refuses to emit a stream whose manifest disagrees with the
  records that followed it.

  "Skipped because unreadable" and "found nothing" are now different facts:
  swinv probes for the dpkg, rpm, apk and portage databases directly, so an
  absent one is `skipped` with a reason and an unreadable one is `error`.

- **Exit code 5**, a source that could not be enumerated, and **exit code 6**,
  a transmission that did not complete or did not reconcile. Exit 5 exists
  because a package database that is present and unreadable produces a small,
  valid, perfectly healthy-looking inventory, and fifteen components from a
  host with four thousand is indistinguishable from a minimal machine. The
  report is still written and `scan.sources` names the source and the reason;
  the exit code is what a timer checks. Exit 6 never destroys the local copy:
  the files are written before anything is uploaded and the spool is kept.

### Changed

- **Schema `1.10`**: `scan.scan_id` and `scan.sources` on the JSON report. Both
  are additive and omitted when never computed, so a `1.9` consumer parses a
  `1.10` document.

- `--transmit` implies the manifest record even without `--heartbeat`, because
  the server opens a scan with it. `--heartbeat` still controls whether an
  unchanged inventory suppresses its component records.

### Fixed

- **Sandboxed system daemons were reported as unmanaged software.** The guard
  that stops a container's executable being joined to host packages keyed on
  the mount namespace alone - and systemd's sandboxing (`ProtectSystem`,
  `PrivateTmp`) gives a unit its own namespace over the same root. On Ubuntu
  24.04 that is `systemd-resolved`, `networkd` and `chronyd`: every one
  reported as "software nothing installed", none probed for libraries. The
  guard now judges by file identity - same device and inode through the
  process's root as through the host's - which clears sandboxed daemons and
  still refuses containers, whose same-named paths are different inodes.
  Found by the CI link assertion on a 24.04 runner; the development host runs
  26.04, which does not sandbox resolved, and never showed it.

## [0.6.1] - 2026-08-23

### Added

- **`--ndjson-include`**, closing
  [#8](https://github.com/chaugan/swinv/issues/8). The NDJSON stream can now
  carry `exposure` and `container` records alongside components. Both sections
  were already collected and written to the JSON document and the CSV sidecars,
  but not to the one output shape a log forwarder monitors - so the format built
  for streaming was the one dropping them.

  `exposure` is denormalised to one record per (port, package), so a
  vulnerability finding joins on the package without the consumer unpacking an
  array. **A port with nothing attributed still produces a record**, with no
  `purl`: a port answering with no package behind it is a gap in what can be
  seen, not a port that is safe. A published container port carries the
  container's id and name, and its `executable` is the process inside the
  container rather than the forwarder.

  `container` is one record per container, **including stopped ones** - a
  stopped container is one `docker start` from a running one, so its
  vulnerabilities are latent rather than absent - carrying the container's own
  `os_id` and `os_version_id`, which is what its packages must be matched
  against.

  Off by default: every NDJSON line was a component before this, so each extra
  record carries a `record_type` an older consumer can skip, and a line without
  one is a component.

  Both are emitted **even on an unchanged `--heartbeat` scan**. The heartbeat
  suppresses the components, which are the volume; a port opening is exactly
  the kind of change that happens while installed software does not. On a
  17-container host that is 46 exposure and 16 container records against 2,715
  components.

  Two shapes chosen for streaming consumers rather than for elegance: **no
  field is ever `null`** - Splunk indexes a JSON null as the four-character
  string `"null"`, which would give every listener a systemd unit named `null`
  - and **every array has a `_text` and `n_` twin**, because Splunk renames an
  array field with a `{}` suffix and a search for `endpoints` otherwise
  silently returns nothing.

## [0.6.0] - 2026-08-22

An inventory heartbeat, so a fleet stops re-sending what has not changed.

### Added

- **`--heartbeat`**, closing [#7](https://github.com/chaugan/swinv/issues/7).
  In NDJSON, one small record at the head of the stream carries a digest of the
  inventory, and the component records are omitted entirely when that digest
  matches the previous scan on this host. Schema `1.9`.

  Every scan otherwise restates the whole inventory. That is the right shape
  for correctness - a package that disappears is genuinely gone rather than
  merely unmentioned - and the wrong shape for volume: 5,000 hosts averaging
  14,000 components scanned hourly is over a billion records a day, nearly all
  identical to the day before.

  **Only NDJSON is affected.** JSON, CSV and CycloneDX carry the full inventory
  every time, because a CSV with no rows would be a false statement about the
  machine where a heartbeat is a true one. **And never a delta**: when anything
  changes the whole list is sent again, because a delta cannot express a
  removal and "this package is no longer installed" is the fact that decides
  whether a vulnerability is fixed or merely unreported.

  The digest is built from identity alone - type, name, version, root, purl -
  and deliberately not from locations, `found_by`, `sha256`, licences, CPEs or
  vendor. Files get relinked and catalogers get renamed upstream; a digest that
  moved with them would report change constantly and be ignored within a week.

  A full list is also sent when nothing is known about the host, when the state
  file cannot be read, on `--force-full`, and whenever `--full-interval` has
  elapsed (default 24h) - so a digest collision or a hand-edited state file
  cannot hide a change indefinitely. Any doubt resolves toward sending too
  much.

  This is the one thing swinv now remembers between runs:
  `.swinv-heartbeat.json` in the output directory, one digest per hostname. A
  dotfile so a collector globbing `*.json` does not pick it up, and beside the
  reports so deleting the output directory deletes the state with it rather
  than leaving a stale digest to claim a fresh machine is unchanged.

## [0.5.2] - 2026-08-22

### Fixed

- **`container_state` is now stamped by both routes.** The runtime route set it
  and the targeted probe did not, so a consumer filtering on it silently
  dropped whatever the probe had found - which is the more precisely
  identified half of the two, the packages tied to a specific listening
  executable.

### Changed

- **The README says what the collector is for.** The comparison table
  explained, for each of four tools, why swinv differs; it never said what
  swinv does that none of them do. The chain - an open port, through the
  forwarder, into the container, to the package inside it - is now the second
  thing in the document and has its own section, with rows added for image
  scanners and agent inventory now that containers are in scope.

## [0.5.1] - 2026-08-22

Two things a v0.5.0 run on a real Windows laptop found, both about the same
seam between the two ways into a container.

### Fixed

- **A running container whose listening executable is not package-owned came
  out with no software at all**, while a stopped one got its whole package
  list. The targeted probe found the executable, found no package owning it -
  which is most application images, where the app is unpacked rather than
  installed - and the runtime read was then skipped because the container was
  already described. That said nothing about the other forty packages in it.
  Six of seventeen containers on the development host; reading them takes the
  container package count from 763 to 1281.
- **`container-packages-not-readable` was declared over 235 packages that had
  just been read.** The check looked only at what the targeted probe recorded
  on the service, and the whole-database read lifts its packages into the
  inventory and leaves the service empty. Both routes are now considered.

## [0.5.0] - 2026-08-22

Containers, running and stopped, on both platforms.

### Added

- **Stopped containers are inventoried, on both platforms.** The question is
  what software on this machine has a network endpoint, and a stopped container
  that declares one is software that will serve on it the moment it is started
   - its packages carry the same advisories either way. It gets no exposure
  row, because nothing is listening.

  This is reached through the container runtime's archive endpoint, which
  returns a file from a container's filesystem whether or not it is running.
  That is also the only route into any container from Windows, so the same
  mechanism closes the `container-packages-not-readable` gap there. Measured on
  the development host: 17 containers instead of 10, and 570 packages from five
  stopped ones - real `pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.23` rows a matcher
  can use.

  Where `/proc/<pid>/root` already answered, it wins: naming the package behind
  a specific listening executable beats listing the two hundred packages that
  share its filesystem. The two are distinguished by
  `attributes.scan_scope`.

- **`Container.state` and `Container.declared_endpoints`.** The declared ports
  are what the image's `EXPOSE` or the run's `-p` says it serves on - a
  declaration, never an observation, and for a stopped container the only
  network fact available. Containers with no endpoint at all, declared or
  observed, are skipped: a build container with no ports is not part of this
  machine's attack surface.

- **A reachable runtime that reports nothing now says so.** "No containers" had
  two causes producing identical output, and a Windows run reported zero on a
  machine with eight stopped containers with nothing to distinguish that from a
  broken pipe.

## [0.4.1] - 2026-08-22

Everything in this release came out of one afternoon of running 0.4.0 on a
real Windows laptop. The attributions it did make were all correct; these are
the ones it failed to make, and the noise it made instead.

### Fixed

- **A product whose only clue was its UninstallString could be named by
  neither route.** `InstallLocations()` already recovers a directory from
  `DisplayIcon` and `UninstallString`, because `InstallLocation` is absent on
  72% of uninstall entries, and the recovered directory was handed to the
  coverage set - so a full scan treated the files under it as accounted for and
  never opened them, producing no PE component. But the component itself took
  its locations from `InstallLocation` alone, so it had no directory either.
  Good enough to suppress the file scan, not good enough to be reported.
  Mosquitto came out of a full scan with a registry entry, no PE component, and
  a listening socket on 1883 that nothing could name. Components now carry every
  directory the entry points at.
- **The kernel process is now named.** No handle can be opened to pid 4, so its
  image was unreadable and the ports it serves - 445, 139, 138, 137 and several
  http.sys reservations, 29 endpoints on one machine - were reported as software
  nobody could identify. It is now `System`, marked `os_component`.
- **An endpoint's sockets fold into one row.** Deduplication was keyed on the
  socket inode and `iphlpapi` supplies none, so on Windows it never fired:
  Brave's twenty mDNS sockets on `0.0.0.0:5353` became twenty identical rows,
  burying the rest of the list. Rows now fold on the endpoint, keeping both
  identities where two programs genuinely share a UDP port, and recording how
  many folded in `processes`. On the machine in question, 189 rows for 158
  endpoints.
- **The services summary called named software unnamed.** It bucketed on
  confidence, so an install-directory match - `medium`, but with a product named
  - was counted as "running software nothing installed". The same scan reported
  0 attributed on one line and 49 identified on another.
- `Exposure.processes` is emitted only where more than one socket shares the
  endpoint, rather than as `1` on every row.

## [0.4.0] - 2026-08-22

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
  resolves to Docker's own proxy - the non-answer this design exists to avoid.
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
  records the directory a product was installed into - `C:\Program Files\7-Zip`
  - and never the executables under it, so nothing ever matched and every
  listener reported as unmanaged software. The longest containing install
  directory now counts, case-insensitively, graded `medium` because a
  containing directory says the product was installed there rather than that
  it ships that particular file.
- **Sockets with no identifiable process vanished from `exposure[]`.** They
  were counted and then dropped, so a privileged run inside WSL2 reported
  twelve listening sockets and zero exposure rows - a machine described as
  having nothing exposed on the strength of not having been able to look. They
  are now reported without a process against them, which is the statement the
  section exists to make.
- **The unattributed-sockets warning blamed the wrong thing.** It said an
  unprivileged scan sees only its own sockets, which was printed verbatim to a
  user running under `sudo`. There are two causes and the message now names
  both: unreadable open files, or a holder outside this PID namespace - the
  latter being exactly what happens under WSL2.

## [0.3.0] - 2026-08-22

What is exposed at the network edge, and what runs inside the containers.

### Added

- **What is exposed at the network edge, and what is running inside the
  containers**, on Linux, and with it schema `1.7`.

  `exposure[]` is one row per listening socket in the **host** network
  namespace, and nothing else - membership is the verdict, so a consumer
  reading only that array cannot mistake a container's `0.0.0.0` bind for a
  host one. `bind_scope` then says how widely each is bound. Deliberately not
  "public"/"private" and never "internet-facing": swinv reads no firewall, and
  `scan.firewall_examined` is emitted as a constant `false` so that reaches an
  ingest pipeline rather than only the documentation.

  `containers[]` is each container and what it listens on inside its own
  namespace, with the identity that makes this useful:
  `pkg:apk/alpine/nginx@1.27.5-r1` from the container's own package database,
  read through `/proc/<pid>/root`. That is a coordinate Grype and Trivy match
  today. An image reference is not - there is no `oci` matcher anywhere in the
  chain, and Dependency-Track will ingest one, find nothing, and show the
  component as clean, which is indistinguishable from safe. The image digest is
  emitted as a locator on its own field and never as an identity.

  A published port follows into the container behind it, so a host endpoint
  names the software that actually answers rather than the package that ships
  `docker-proxy` - which was 14 of 31 services on the development host.

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
  under the cgroupfs driver - and on Kubernetes, and under LXC - a container's
  process looked like a host process and had its executable matched against the
  *host's* package databases. A container running `/usr/sbin/nginx` on a host
  that also has nginx got the host's package, the host's version, and
  confidence `high`. Detection is now on the shape of the cgroup path, and the
  guard no longer depends on recognising a layout at all: a process in a
  different mount namespace than init is never joined to host packages.

- **CycloneDX output carried no distro.** Syft's decoder - which is what Grype
  uses for `grype sbom:`, a recipe this project documents - reads the Linux
  release only from a `components[]` entry of type `operating-system`, and
  swinv emitted none. Every deb and rpm therefore arrived with no distro, and
  matching fell back to comparing backported versions against upstream
  numbering: the same failure that produced 442 false findings on one host, this
  time caused by the output format itself.

- **What is listening is now part of the inventory**, on Linux, and with it
  schema `1.6`. A new top-level `services[]` array records each listening
  socket, the process behind it, its systemd unit and container, and which
  installed software owns its executable - with a `confidence` and an
  `evidence` trail, because a service finding is assembled from evidence of
  varying strength and a bare claim that "port 443 is nginx 1.24" is
  indistinguishable from a guess.

  The interesting rows are the `medium` ones: software that is serving traffic
  and that no package manager installed. A package inventory cannot produce
  that finding at all. On the development host it is three of thirty-one - a
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
  omits just the `command` field. Command lines are where secrets end up - a
  `--password` on a daemon's ExecStart, a connection string with credentials in
  it - and an inventory file is usually copied somewhere with a different
  audience. [SECURITY.md](SECURITY.md) now says so plainly.
- **Base snaps are recognised as their own filesystem root**, so the components
  inside them stop being attributed to the host. A base snap is a different
  operating system - `core18` is Ubuntu 18.04 while the host may be 26.04, with
  its own package set and its own update cadence - and 862 components on one
  reported host all claimed `root: "/"`. Where a nested root states its own
  release, `attributes.root_os_id` and `attributes.root_os_version_id` now carry
  it, rather than leaving consumers to infer 18.04 from the name `core18`.
- **Python and npm packages are now inventoried on Windows** under
  `--full-scan`. The Linux collector gets roughly forty ecosystems from Syft and
  the Windows collector could get none, because Syft's resolver opens every file
  it indexes - measured as unworkable on Windows, where every open is inspected
  by antivirus. Instead, MFT enumeration already produces every filename without
  opening anything, and installed packages announce themselves by name:
  `*.dist-info/METADATA`, `*.egg-info/PKG-INFO`, `package.json`. Only those files
  are opened. They carry real PURLs, since unlike registry entries these
  ecosystems have canonical PURL types.

## [0.2.3] - 2026-08-21

One reported issue: distribution-installed language packages now name the OS
package that owns them.

### Added

- **`Component.owned_by`** links a distribution-installed language package to
  the OS package that owns its files, and with it schema `1.5`. Syft already
  computes this and swinv was discarding it: the deb's file list contains the
  very `egg-info` path the Python cataloger read. Both rows are still reported -
  the OS package is what the vendor patches, the ecosystem package is what
  upstream advisories are written against - but a consumer assessing the second
  against upstream was comparing a backported version with upstream's own
  numbering. One reported host produced 442 false findings that way, because
  Ubuntu's `cryptography 2.1.4+esm1` is patched while PyPI's `2.1.4` reads as
  thirty-seven releases behind. An empty `owned_by` is equally meaningful: the
  component came from `pip` or `npm` and genuinely should be checked upstream.

## [0.2.2] - 2026-08-21

Four issues reported by someone building an offline vulnerability matcher
against swinv output, and the Windows update model rebuilt on what the
component store actually records.

Two of the four were dangerous rather than untidy: a placeholder version that
parses as a valid low version, and packages in nested roots carrying the
scanning host's distribution. Both produced output that looks like an answer
and is not one, which is the worst way for an inventory to fail.

### Added

- **`Component.root`** records which filesystem root a component was found in -
  `/` for the scanned machine, or a nested root such as a snap base or a
  container layer - and participates in deduplication. Two packages of the same
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

## [0.2.1] - 2026-08-21

Windows now sees Store apps and installed updates, both from the registry and
neither costing a file open, so they are in the default scan rather than behind
`--full-scan`.

### Added

- **Store and MSIX packages** are now inventoried, from the AppModel package
  repository. Read without opening a file, so this runs in the default scan
  rather than behind `--full-scan`. Resource bundles are filtered out - one
  ships per display scale and per language, and counting them turns a single
  application into a dozen rows differing only in an asset resolution - as are
  packages under `Windows\SystemApps`, which are the shell rather than
  installed software.
- **Installed Windows updates**, by KB number, from the component store. Not
  from `Win32_QuickFixEngineering`, which is what `Get-HotFix` reads: on a
  machine whose component store held 7,844 package entries, that class reported
  three updates. The store records one key per component per update, so KB
  numbers are deduplicated, and the component count behind each is kept.

### Changed

- **Operating-system components are out of scope by decision rather than by
  omission.** `C:\Windows\WinSxS` held 39,536 executables on a real machine -
  40% of every candidate on the volume - and they are hard-linked servicing
  copies that say little individually. The installed-updates list expresses the
  same thing in the form an operator patches by. The warning now says this
  instead of promising catalogers that were never going to be worth writing.

## [0.2.0] - 2026-08-21

Windows support, and a schema that carries who made a thing.

`swinv.exe` now collects an inventory rather than failing slowly at one. It is
**experimental**: one week old, exercised on CI and a single developer laptop,
with real gaps named in [docs/WINDOWS.md](docs/WINDOWS.md) - operating-system
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
  covered by the same `SHA256SUMS`. A binary only - no MSI, which would claim a
  maturity this does not have.

- **MFT enumeration for Windows** (`internal/usn`), the first piece of the
  Windows collector that is not the Linux one cross-compiled. It reads a record
  per file straight from the Master File Table via `FSCTL_ENUM_USN_DATA`,
  opening nothing. On a stock Windows 11 volume it read **1,301,728 records in
  42 seconds** and kept the **9.8%** that are executables - the other 90.2% cost
  one record each and are never touched, where a directory walk would have
  opened all 1.3 million. `C:\Program Files` alone, a fraction of that volume,
  does not finish inside ten minutes through the directory resolver. Not yet
  wired into the scan path.
- **A working Windows collector.** `swinv.exe` now produces a real inventory
  instead of running the Linux filesystem scan on a platform that keeps its
  records elsewhere. It reads the uninstall registry for installed products -
  fast, no elevation, no file opened - and with `--full-scan` enumerates the
  MFT, attributes each executable to a known product, and opens only what is
  left to read its PE version resource. `--volumes D:` or `D:,E:` selects which
  volumes to enumerate, replacing the default of `C:` rather than adding to it.
- **`Component.attributes`**, a string map for ecosystem-specific identity -
  Windows product codes, registry keys, install scopes, the several version
  strings a PE resource carries - and with it schema `1.3`. In JSON and
  CycloneDX properties, deliberately not in the CSV, whose fixed column shape
  is what lets files be concatenated across machines.
- **The Windows architecture is now measured rather than reasoned.** The
  proposed derived allowlist does not hold up - only 106 of 380 installed
  products record an `InstallLocation`, and adding `DisplayIcon` and
  `UninstallString` raises that to 147, covering 57.8% of third-party
  executables. What the measurement showed is that the allowlist was pointed
  the wrong way: enumeration is cheap (a 2.9-million-record volume in under
  five seconds, nothing opened) and *extraction* is what costs. A file under a
  known product's directory already has its version from the registry, so
  registry coverage is an extraction filter, not a scan filter. Applied that
  way it cuts files needing to be opened from 99,919 to 19,549 - 80% fewer.
- **The Windows uninstall registry reader** (`internal/arp`), which is the
  Windows equivalent of reading a package database: names, versions, publishers
  and install locations, with no file opened. It covers all three scopes -
  native `HKLM`, `WOW6432Node` for 32-bit installs, which are invisible to code
  that reads only the native key, and `HKCU`. Never via `Win32_Product`, whose
  enumeration triggers MSI repair and can modify the machine.
- **`--usn-probe` and `--volumes`**, Windows-only and experimental. The probe
  enumerates the MFT and reports what it found - record count, candidate count,
  timing, and where the candidates live - without scanning or opening anything,
  so the numbers that decide the rest of the Windows design come from real
  machines rather than from a hosted runner with nothing installed on it.
  `--volumes D:` or `--volumes D:,E:` **replaces** the default of `C:` rather
  than adding to it. Passing `--volumes` without `--usn-probe` is a usage error
  rather than being ignored, so nobody believes they have restricted a scan
  when they have not.
- **CI now runs natively on `windows-latest`**, which is elevated and NTFS -
  the two things MFT enumeration requires. `docs/WINDOWS.md` set a condition
  that no Windows work should begin without a machine to test on, and a hosted
  runner satisfies it.
- **`Component.vendor`**, the organisation behind a component, and with it
  schema `1.2`. It comes from whichever field the ecosystem uses - an rpm
  `Vendor`, a dpkg or apk `Maintainer`, a Python or npm `Author`, `Vendor` from
  a systemd ELF package note, or `CompanyName` from a Windows PE version
  resource, which is what makes a `.dll` attributable to its publisher. The raw
  value is kept rather than normalised, because a Debian maintainer and a
  Microsoft `CompanyName` are related but not identical facts. Additive: JSON
  omits it when empty, `vendor` is appended as CSV column 18 so positional
  readers are unaffected, and CycloneDX maps it to `publisher`. Present on 23%
  of components on a full Debian-family host - 66% of `deb`, 0% of kernel
  modules - so absence means "not recorded", not "no vendor".
- **swinv now gets out of the way of the machine it is inventorying.** By
  default a scan runs at `nice 10` with the idle I/O scheduling class on Linux,
  in background priority mode on Windows, and with a quarter of the CPUs as
  cataloger workers rather than all of them. An inventory collector is
  background maintenance - unattended, on a timer, on a machine doing real
  work - and a scan that finishes sooner but makes an interactive session
  stutter has made a bad trade. `--fast` restores the previous behaviour for
  when a person is waiting: measured on `/usr` on an 8-core host, the default
  takes 41.6 s against 30.6 s with `--fast`, so politeness costs about a third
  of the runtime. An explicit `--parallelism N` still overrides both.
- **`--debug-stacks-after DURATION`** writes every goroutine stack to a file
  while a scan is still running, for diagnosing one that appears to have hung.
  Go already does this on `SIGQUIT`, and on Windows on Ctrl+Break, but neither
  is reachable from a systemd timer or a Windows scheduled task, and many
  laptops have no Break key - which is exactly the situation the first Windows
  tester was in.
- **A long scan now says it is still alive**, every 30 seconds, with elapsed
  time, memory taken from the operating system, and the deadline. Memory is on
  the line because its growth is what distinguishes a scan that is merely slow
  from one that has started paging and dragged the whole machine down with it -
  a distinction that cost an afternoon of diagnosis when the heartbeat itself
  went silent for nine minutes on a Windows host. Between "scanning ..." and the result there was
  previously no output at all for up to 30 minutes, so a slow scan and a hung
  one were indistinguishable - which is exactly how the first Windows run was
  read, and reasonably so.

- `docs/SERVER-ROLES.md`, the proposed design for detecting what is running and
  serving - as distinct from what is installed - on both platforms, including
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
  warning - not running as root, unidentified files, filesystems skipped -
  went into the JSON where only someone who opened it would find them.

### Fixed

- **`ran_as_root` was always `false` on Windows, including for an elevated
  Administrator.** `os.Geteuid` returns a hard-coded `-1` there - not an error
  and not an unsupported marker - so the check reported "unprivileged" for a
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

## [0.1.2] - 2026-08-19

### Fixed

- **A `--root` other than `/` got no exclusions at all**, so scanning a mounted
  root filesystem walked its `proc`, `sys` and every home directory on it. Found
  by running the container recipe from the README - `-v /:/host:ro --root /host`
  - which hung rather than completing. A tree containing `etc/os-release` is now
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
  296/296, Ubuntu dpkg 1,587 against 1,586 installed - correctly excluding 11
  packages removed with their config kept. The Alpine run also proves the
  `CGO_ENABLED=0` binary carries no glibc assumption.

- The CycloneDX handoff to `grype` was executed end to end for the first time.
  `grype` v0.117.0 accepted a 568-component document from a Fedora 44 host and
  returned 234 vulnerability matches across `rpm` and `go-module` components.
  Because CVE matching is a join on package identity, this also confirms the
  emitted PURLs are well-formed - the CycloneDX writer is built from
  `cyclonedx-go` rather than reusing Syft's encoder, so that was not a given.
- The Go module and binary catalogers ran against real Linux binaries on a
  non-Debian host.

## [0.1.1] - 2026-08-19

### Fixed

- **Host-shared filesystems were scanned, so another operating system's
  software was reported as installed on this one.** The non-local filesystem
  list covered network and virtual filesystems but not the ones a hypervisor
  or WSL uses to project the *host's* directories into a guest. On a Fedora 44
  guest under WSL2, `/usr/lib/wsl` is a `9p` mount carrying the Windows host's
  driver packages: 477 of that host's 1,003 components - 48% of the whole
  inventory - were ASUS, Intel and NVIDIA binaries and .NET assemblies
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

## [0.1.0] - 2026-08-19

First public release.

### Added

- Scans a Linux host and enumerates installed software - OS packages
  (dpkg, rpm, apk, pacman, portage, nix, Homebrew, snap), roughly 40 language
  ecosystems, and loose binaries - by importing
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

As of `v1.0.0`, `swinv` follows semantic versioning: the CLI surface and the
output schema are stable, a minor bump is additive and safe for existing
consumers, and a breaking change is reserved for a new major version and called
out here.

The output document carries its own `schema_version`, currently `1.18`,
independent of the tool version. It follows semver in its own right: a minor
bump is additive and safe for existing consumers, a major bump is breaking.

[Unreleased]: https://github.com/chaugan/swinv/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/chaugan/swinv/releases/tag/v1.0.0
[0.9.7]: https://github.com/chaugan/swinv/releases/tag/v0.9.7
[0.9.6]: https://github.com/chaugan/swinv/releases/tag/v0.9.6
[0.9.5]: https://github.com/chaugan/swinv/releases/tag/v0.9.5
[0.9.4]: https://github.com/chaugan/swinv/releases/tag/v0.9.4
[0.9.3]: https://github.com/chaugan/swinv/releases/tag/v0.9.3
[0.9.2]: https://github.com/chaugan/swinv/releases/tag/v0.9.2
[0.9.1]: https://github.com/chaugan/swinv/releases/tag/v0.9.1
[0.9.0]: https://github.com/chaugan/swinv/releases/tag/v0.9.0
[0.8.0]: https://github.com/chaugan/swinv/releases/tag/v0.8.0
[0.7.1]: https://github.com/chaugan/swinv/releases/tag/v0.7.1
[0.7.0]: https://github.com/chaugan/swinv/releases/tag/v0.7.0
[0.6.1]: https://github.com/chaugan/swinv/releases/tag/v0.6.1
[0.6.0]: https://github.com/chaugan/swinv/releases/tag/v0.6.0
[0.5.2]: https://github.com/chaugan/swinv/releases/tag/v0.5.2
[0.5.1]: https://github.com/chaugan/swinv/releases/tag/v0.5.1
[0.5.0]: https://github.com/chaugan/swinv/releases/tag/v0.5.0
[0.4.1]: https://github.com/chaugan/swinv/releases/tag/v0.4.1
[0.4.0]: https://github.com/chaugan/swinv/releases/tag/v0.4.0
[0.3.0]: https://github.com/chaugan/swinv/releases/tag/v0.3.0
[0.2.3]: https://github.com/chaugan/swinv/releases/tag/v0.2.3
[0.2.2]: https://github.com/chaugan/swinv/releases/tag/v0.2.2
[0.2.1]: https://github.com/chaugan/swinv/releases/tag/v0.2.1
[0.2.0]: https://github.com/chaugan/swinv/releases/tag/v0.2.0
[0.1.2]: https://github.com/chaugan/swinv/releases/tag/v0.1.2
[0.1.1]: https://github.com/chaugan/swinv/releases/tag/v0.1.1
[0.1.0]: https://github.com/chaugan/swinv/releases/tag/v0.1.0
