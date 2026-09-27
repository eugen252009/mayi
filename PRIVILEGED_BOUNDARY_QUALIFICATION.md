# Historical qualification: isolated privileged boundary (superseded)

This document records the earlier qualification-only fixed-operation boundary. It does **not** qualify the current `mayi` exact-command MVP, its generic root executor, or the authorization-to-executor handoff. For current package qualification and scope, see `executor/package/README.md` and `SECURITY_BOUNDARY.md`.

## Historical package evidence

The earlier TPA build was `mayi-privileged-boundary-qualification_0.1.0_amd64.deb`, with `TPA-Version: 0.4.0`, creation time `2026-09-26T14:29:17Z`, and SHA-256 `b12e54c0cfe9a74243c7eb7953c2729660fa072e8c4678e5825bcfee8fe4ddae`. It is a historical artifact; the current package is `mayi_0.2.0_amd64.deb` and has separate qualification evidence.

The old qualification tested a closed harmless `QualificationEffect`, broker-UID `SO_PEERCRED` authentication, fixed framing, journal replay protection, malformed frames, concurrency/restart, role denial, and package lifecycle in disposable Debian 12 Docker. No host privileged effect was performed. Its probe was not the production broker, did not read or consume Protocol 5 authorization, and did not test an approved command.

The earlier unit was inspected but systemd did not start it because the container PID 1 was not systemd. None of that old evidence establishes the current systemd startup behavior.

## Current status

The current MVP now has a separate privileged executor for exact, structured executable/argv requests. Its independent security review is outside the scope of the historical result. Current end-to-end package test evidence is recorded in `executor/package/README.md` and `DEBIAN_COMPATIBILITY.md`; it qualifies disposable Debian 10–13 package flows and also records the administrator-reported real Debian 12.15 smoke test. No legacy Debian kernel was boot-tested. The filesystem executor remains disconnected and independently **INCOMPLETE**.

`SO_PEERCRED` authenticates an OS UID, not a process, executable, or human. No host service reload, host privileged action, or live filesystem mutation is authorized by this historical record.
