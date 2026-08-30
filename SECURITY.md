# Security policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub's
[private vulnerability reporting](https://github.com/chaugan/swinv/security/advisories/new)
rather than opening a public issue.

Include the `swinv --version` output, the distribution and architecture, whether
the run was privileged, and the smallest reproduction you can manage. If a scan
is involved, the `scan.warnings` and `scan.excluded` arrays from the report are
usually the most useful thing you can attach.

`swinv` is a `v0.x` volunteer project with no paid on-call. Expect an
acknowledgement within a week. Fixes ship in the next tagged release; there is
no separate backport stream yet.

## What `swinv` does with your data

This matters more than usual here, because the tool's whole job is to read the
machine it runs on.

- **No inventory data is ever transmitted.** `swinv` opens no sockets to send
  results anywhere. There is no telemetry, no update check, and no phone-home.
- **One optional network call.** A best-effort reverse-DNS lookup fills
  `host.fqdn`. It is ordinary name resolution against your configured resolver,
  bounded to two seconds, never fatal, and carries no scan data - but it does
  tell that resolver the host looked itself up. **`--offline` disables it**, at
  which point the run performs no network activity at all. It is skipped
  automatically whenever `--root` is not `/`.
- **Reports identify the machine.** They contain the hostname, `/etc/machine-id`,
  boot ID, kernel version, DMI vendor and product, and non-loopback IP and MAC
  addresses. That is what makes reports joinable across a fleet, and it is also
  why the output files deserve the same handling as any other asset inventory.
  DMI serial and UUID are readable only as root and are simply absent otherwise.
- **Reports list installed software and its paths.** With `--include-home` those
  paths include the contents of users' home directories, which is the main
  reason home directories are excluded by default.
- **Reports list what is listening, including full command lines.** The
  `services` block records each listening socket, the process behind it, and
  that process's `argv`. Command lines are frequently where a secret ends up:
  a `--password` on a daemon's ExecStart, a token in a wrapper script, a
  connection string with credentials in it. Anything visible in `ps` to a user
  on the machine can therefore end up in an inventory file that is copied
  somewhere with a different audience. **`--no-service-command` omits the
  `command` field**, keeping the endpoint, the executable, the unit and the
  attribution; **`--no-services` skips the whole section**. Collecting services
  also means reading `/proc/<pid>/fd` for processes swinv does not own, which
  needs root - unprivileged, the ports are still reported and the processes
  behind them mostly are not.
- **It reads container filesystems.** Identifying the software behind a
  published port means reading each container's own package database through
  `/proc/<pid>/root`, which is root-only. That filesystem's contents are chosen
  by whatever runs in the container, so every read there is size-capped and
  refuses anything that is not a regular file, and only fixed paths are opened
  - no part of a path comes from the container. `--no-containers` disables it,
  at the cost of not being able to name any containerised software.
- **It talks to one daemon, and only one.** On Windows, identifying what is
  behind a published container port requires the local Docker engine's named
  pipe, because a Docker Desktop container is a Linux process inside a virtual
  machine that no Windows API reaches. `swinv` connects to
  `\\.\pipe\docker_engine` (and the Unix socket equivalent elsewhere), reads
  the container list, and does nothing else - no create, no exec, no attach.
  This is local kernel IPC, not network activity: there is no address and no
  route, and nothing leaves the machine. `--no-containers` disables it. Note
  that reaching the engine implies membership of `docker-users` or equivalent,
  which is itself a privileged position on the host.
- **The exposure list is not a reachability claim.** `swinv` reads no firewall,
  no NAT table and no cloud security group. `bind_scope` describes the bind and
  nothing more, `scan.firewall_examined` is emitted as a constant `false`, and
  `scan.exposure_blind_spots` names what could not be observed - including
  Kubernetes NodePort and any port published by a netfilter rule with no
  process behind it, which are invisible by construction. **A short exposure
  list is not evidence that little is exposed** until that array has been read.
- **Output permissions default to permissive, and are configurable.** Reports
  are written `0644` in a `0755` directory so a collector running as another
  user can read them, which is the documented deployment model. The cost is
  that any local user can read a file identifying the host and listing its
  software. Use `--perm 0640` to restrict to the owning group or `--perm 0600`
  to the owner alone; the directory mode is derived from it.

## Running it safely

- Prefer the shipped systemd unit. It sets `ProtectSystem=strict`,
  `ReadWritePaths=/var/lib/swinv`, `PrivateTmp`, `NoNewPrivileges` and the
  `ProtectKernel*` family. It deliberately does **not** set `ProtectHome`,
  `PrivateDevices`, `PrivateUsers` or `ProtectProc=invisible`, each of which
  would hide something the scan needs.
- Running unprivileged is fully supported and is the safer default. It costs
  root-only paths and the DMI serial/UUID, and records a warning saying so.
- `swinv` only ever reads. It writes nothing outside `--out`.

## Trust boundaries you should know about

- **`swinv` parses untrusted input by design.** Package databases, manifests and
  binaries on the scanned host are attacker-influenced on a compromised machine.
  Most of that parsing happens inside [Syft](https://github.com/anchore/syft);
  a parser vulnerability there is reachable through `swinv`. We pin Syft to an
  exact version and update it deliberately.
- **`--since` reads a JSON report you supply.** Point it at a file you trust.
- **The dependency licence gate is not a security control.** It prevents
  copyleft contamination, nothing more.

## Hardening against a local attacker

swinv runs as root or SYSTEM on hosts that also have unprivileged local
users. A structured review asked what such a user could do *because* swinv is
privileged, across six dimensions, and its findings consolidated to nine root
causes - each adversarially verified against the code. All nine are addressed;
the principle throughout was to change how swinv reads and writes, not what it
reports, verified by diffing a full before/after scan of a reference host.

A structured review across six dimensions (output/symlink/TOCTOU, information
disclosure, attacker-controlled input parsing, secrets and privileged-daemon
access, resource exhaustion, and Windows-specific) produced findings that
consolidated to **nine root causes**, each adversarially verified against the
code before being accepted. All nine are addressed.

### R1 - Windows: SYSTEM writing into an attacker-controlled directory *(high)*

`C:\` grants `BUILTIN\Users` "create folders", inherited into new
subdirectories, so an unprivileged user could pre-create the `--out` path,
become its owner, and then read everything SYSTEM wrote there and overwrite
what it transmitted (including forging the spool and heartbeat state). POSIX
`--perm` bits are inert on Windows.

**Fix.** `secureOutputDir` (Windows) creates the output directory with an
explicit, non-inherited DACL granting only SYSTEM and Administrators, and
**refuses to run** when an existing `--out` is owned by any principal other
than SYSTEM, Administrators, or the account running the scan. The transmit
spool and heartbeat state live under that now-protected directory.

*Strengthened in 1.0.1:* the directory is secured once, by `ensureOutputDir`,
**before the scan starts and before anything writes under `--out`**. Two
ordering gaps were closed: the heartbeat state writer used to create the
directory itself with a plain `MkdirAll` - inheriting the parent's permissive
ACLs and voiding the protected DACL whenever `--out` did not exist yet - and a
`--stdout --transmit` run bypassed the check entirely, leaving the spool in an
unvetted path. Both writers now find the directory already guarded, and the
guard creates missing parents so the default `C:\var\lib\swinv` works on a
machine where they do not exist.

### R2 - `authorized_keys` read from an attacker-owned home *(high)*

Under the default config scope the root process read every account's
`~/.ssh/authorized_keys`, including the attacker's own home, with an unguarded
`os.ReadFile` that followed symlinks and had no size cap. A symlink to
`/dev/zero` caused unbounded memory growth (OOM), to a FIFO blocked the read
past any deadline (hang), and to `/root/.aws/credentials` had root read a
root-only file whose contents then entered the report the attacker can read.

**Fix.** All configuration-surface reads open the file `O_NONBLOCK` and then
**fstat the opened descriptor**, refusing anything that is not a regular file -
so a symlink to `/dev/zero`, a device, or a **FIFO** (which would otherwise
block the root process inside `open(2)` waiting for a writer) is rejected
without hanging. `authorized_keys` additionally goes through an **ownership
gate** (`readOwnedByCapped`): a file reached through a symlink must be owned by
the account itself, so a symlink pointing at a root-owned file such as
`/root/.aws/credentials` is refused; a genuine (non-symlinked) root-owned key
file, which a hardened `sshd`'s StrictModes permits, is still read. A legitimate key file is owned by its
own account and is read unchanged; a symlink to a differently-owned file is
refused. *Output note:* a deployment that legitimately symlinks
`authorized_keys` to a file owned by a different account would lose that row;
verified absent on the reference host.

### R3 - Root-only privilege data in a world-readable report *(high)*

Sudo rules (with NOPASSWD/broad-grant evidence), cron and systemd command
lines, ssh-key comments, and the Windows IFEO debugger line were collected and
written to the default 0644 report. `--no-service-command` did not cover the
sudo, ssh-key, or IFEO fields.

**Fix.** `--no-service-command` now correctly redacts the sudo NOPASSWD/broad
evidence, the ssh-key comment, and the IFEO debugger line, matching every other
command line. The *default* still collects them (the tool's documented model is
"collect, then the operator restricts the files"); operators who share the
report should pass `--no-service-command` and/or tighten `--perm`. See R4.

### R4 - Report and spool written world-readable *(medium)*

The report defaults to 0644 and the transmit spool inherited `--perm`, so on a
host where `proc hidepid` hides other users' command lines, the report handed
them back anyway. 

**Fix.** The **transmit spool is forced 0600/0700** regardless of `--perm` - it
is swinv's private staging area and always holds the full scan. The report
mode remains operator-controlled (`--perm`); the disclosure surface is
documented here and in the report's own Security section so an operator sharing
the file at 0644 does so knowingly. *No content change.*

### R5 - Goroutine dump written to a predictable temp path *(medium)*

`--debug-stacks-after` wrote `swinv-stacks-<timestamp>.txt` into shared
`os.TempDir()` with `O_CREATE|O_TRUNC`, letting an unprivileged user pre-plant
the path to capture the dump or symlink it onto a root file.

**Fix.** The primary write uses `O_EXCL|O_NOFOLLOW`; the fallback uses
`os.MkdirTemp`+`os.CreateTemp` for an unpredictable, exclusively-created file.

### R6 - SUID walk memory inflation *(low)*

Under `--config-scope all` the walk descended into world-writable directories,
where an attacker could `chmod u+s` thousands of files they own (no privilege,
but it trips the setuid check) to inflate the root process's memory.

**Fix.** The number of *recorded* setuid entries is capped, and under
`--config-scope all` a setuid file owned by a non-root user is skipped - it
runs as that unprivileged user and is no escalation. The standard scope walks
only system binary directories and is unchanged. *Output note:* on a normal
host every real setuid binary is root-owned, so the recorded set is unchanged;
verified on the reference host.

### R7 - Uncapped reads across the configuration surface *(low, defense-in-depth)*

Beyond `authorized_keys`, the other config reads (cron, units, sudoers, passwd,
modules, preload) used unbounded `os.ReadFile`.

**Fix.** All routed through `readCapped` (regular-file gate + 8 MiB cap). Real
configuration files are far below the cap; a pathological file degrades one
inventory row instead of the host.

### R8 - Crafted `DT_NEEDED` naming an arbitrary host path *(low)*

A listening binary with `DT_NEEDED="../../../etc/shadow"` had the root ELF probe
stat and header-read the named file and record the un-normalised path (no
contents leaked - non-ELF is discarded).

**Fix.** The resolver returns `path.Clean`ed paths, and a slash-bearing soname
(never legitimate - a `DT_NEEDED` is a bare name) is rejected before resolution.

### R9 - Inconsistent credential-file checks *(low)*

The passphrase file check followed symlinks, checked mode but not ownership,
and raced the read; the token and client-key files had no check; the check was
a no-op on Windows.

**Fix.** Credential files open through `openCredential`: `O_NOFOLLOW`, then
`fstat` on the descriptor verifying owner (root/self) and mode `0600`, closing
the symlink-follow, ownership gap, and stat/read race together. Applied to the
token and passphrase files; the Windows path relies on directory ACLs (R1).

## Verified: no functionality lost

The fixes were vetted by scanning a reference host with the pre-change and
post-change binaries under identical flags and diffing the records. The
configuration-surface records (all nine kinds, every field) came out
**byte-identical**: the ownership gate, the capped readers, the redaction
plumbing and the setuid handling changed how the files are read, not which
entries or fields result. The only intentional output change was R8: one link
path canonicalized from `/usr/local/bin/../lib/libpython3.12.so.1.0` to
`/usr/local/lib/libpython3.12.so.1.0` - the same file, cleaned - which is the
traversal-hardening working as designed.

## Regression coverage

Each fix carries a test so the vulnerability cannot silently return:

- the `authorized_keys` ownership gate has tests that a FIFO, a *symlink to* a
  FIFO, and a symlink to a file the account does not own are all refused
  rather than hanging the scan or leaking the target's contents, and that a
  legitimate user-owned key file is still read;
- the setuid walk has tests for the recorded-entry cap and the
  `--config-scope all` skip of non-root-owned files;
- the ELF probe has a test that a slash-bearing, traversal-shaped soname does
  not resolve to an un-jailed host path;
- the installer/launcher classifier has tests for the wrapper cases and, as
  importantly, for the standalone cases it must never flag.

The build also runs `golangci-lint` with `gosec` on every change; the DLL-load
and file-permission findings above were partly surfaced by it, and it fails
the build on a regression such as a credential opened without `O_NOFOLLOW` or
a file created world-writable.

## Verified safe (no action)

- **No DLL-hijack vector.** Every Windows system DLL is loaded via
  `windows.NewLazySystemDLL` (System32-only) or the `x/sys/windows` version
  APIs; there is no `NewLazyDLL`/`LoadLibrary` by bare name that an
  unprivileged user could redirect via the current directory or PATH.
- The container-root re-rooting jail and the ELF resolver's regular-file gate
  were each checked and found to correctly bound the impact of R8.

## Operator guidance

- On a shared host, either run swinv with `--no-service-command` (redacts
  command lines, sudo evidence, ssh-key comments, IFEO lines) or write the
  report to an admin-only directory and/or `--perm 0600`.
- On Windows, prefer an output directory under `%ProgramData%\swinv`; swinv
  will refuse an `--out` a non-admin owns.
- Keep credential files (`--transmit-token-file`, `--transmit-key`,
  `--transmit-key-passphrase-file`) mode 0600 and root-owned; swinv refuses
  them otherwise. Prefer a systemd credential for the passphrase.

## Supported versions

Only the latest tagged release is supported. `swinv` has not reached `v1.0.0`;
until it does, the output schema may still change with a `schema_version` bump
called out in the release notes.
