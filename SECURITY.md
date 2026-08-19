# Security policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub's
[private vulnerability reporting](https://github.com/chrzz/swinv/security/advisories/new)
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
  bounded to two seconds, never fatal, and carries no scan data — but it does
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
- **Output permissions are deliberate but permissive.** `--out` is created
  `0755` and files `0644`, so an inventory is world-readable on the host.
  Tighten this if your threat model requires it.

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

## Supported versions

Only the latest tagged release is supported. `swinv` has not reached `v1.0.0`;
until it does, the output schema may still change with a `schema_version` bump
called out in the release notes.
