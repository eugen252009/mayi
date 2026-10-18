# Mayi security boundary — published baseline 0.4.1 / candidate 0.4.1-5

> **Development 0.4.1-9~ui3:** explicit, broker-enforced five-minute sliding console authentication sessions are now implemented. Successful decisions renew the window; reads do not. This supersedes per-decision password claims below for the new console only. Legacy clients still use per-decision PAM. See [AUTHENTICATION_SESSIONS.md](AUTHENTICATION_SESSIONS.md) for protocol, threat-model changes and test limits. Not packaged, deployed or production-qualified.

## Guarantees in the published package

- **Broker-owned request state:** the broker validates and stores the exact resolved executable path and argv. Requester-supplied approval fields, rendered text, environment, cwd, and file descriptors are not execution authority/input.
- **Independent identity and role checks:** broker request/approval peers are authenticated with kernel `SO_PEERCRED`; requester and approver roles are checked against NSS groups. The executor separately accepts only the configured broker UID.
- **Published 0.4.1 PAM limitation:** PAM is enforced by the supplied console client, not by the broker approval protocol. A direct approval-socket client can bypass console-local PAM while satisfying broker NSS group/view checks. Published 0.4.1 therefore does **not** guarantee PAM authentication for every protocol approval. This was reproduced against the exact 0.4.1-2 artifact; 0.4.1-2 remains unchanged and unpublished.
- **One-shot decision lifecycle:** a decision uses a fresh broker view bound to the request and actual approver UID. The broker consumes approved state at most once. For queues, each operation needs approval and all dependencies must succeed before execution.
- **Exact process execution:** only the broker's immutable `exec` operation reaches the privileged executor. The executor repeats validation, records a one-shot replay claim, clears the environment, and launches the executable directly with argv—no implicit shell.
- **No direct requester/approver executor path:** the executor socket authenticates the broker UID. Socket access alone is not authorization.
- **0.4.1 console UX:** successful authentication is quiet. After a fully correlated successful allow/deny/follow-up decision, supported TTYs clear only the visible screen; scrollback is preserved. Failed decisions preserve the display.

These properties do not close the published 0.4.1 approval-protocol PAM bypass. Do not describe published 0.4.1 as requiring PAM for every broker decision.

## Candidate 0.4.1-5 PAM authority boundary

Candidate `0.4.1-4` moves PAM from a console-local gate into a separate broker-verifiable service. Each decision transports one controlling-terminal descriptor to the unprivileged broker using `SCM_RIGHTS`. Rust validates the actual approval peer UID through NSS, checks the active/unexpired request view before authentication, forwards a correlated tuple and the kernel-derived UID to the PAM authority, and rechecks NSS group membership and decision state under the broker lock after authentication.

The PAM authority runs as UID 0/GID 23012 because Debian's stock `pam_unix`/`unix_chkpwd` path cannot authenticate another local UID from an unprivileged service. It is **not** an unprivileged helper and is privileged code. Its systemd unit bounds permitted/effective/inheritable/ambient capabilities to `CAP_DAC_READ_SEARCH`, sets `NoNewPrivileges=yes`, uses `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, namespace/kernel restrictions, and permits writes only to the PAM socket and `/run/faillock`. It does not receive broker decision state and has no command-execution path. A PAM stack may contain host-configured modules; those modules and the helper remain part of the trusted computing base.

The helper requires both `SO_PEERCRED` UID 23002 and the peer process's membership in the protected `/system.slice/mayi-broker.service` cgroup. It deliberately does not inspect `/proc/<pid>/exe`, because it lacks `CAP_SYS_PTRACE` and cross-UID executable inspection is ptrace-gated. A same-UID process outside the service cgroup was tested and rejected. The cgroup identity is fixed and systemd-specific: custom unit/slice placement or non-systemd operation fails closed. Host root/systemd administration and the broker service are trusted; this does not protect against their compromise or against a privileged actor moving a process into the broker cgroup.

Each decision runs the configured `/etc/pam.d/mayi-approve` authentication and account policy for the NSS username mapped from the broker-derived UID. No password, reusable assertion, PAM handle, or authenticated session is carried in broker JSON or reused. The helper bounds authentication to 300 seconds and applies an in-memory throttle of five failed attempts per UID per 10 minutes; restarting the helper resets this throttle. It is an online-abuse control, not durable account lockout. Only Debian's stock local PAM stack was end-to-end qualified; third-party MFA/SSSD/custom modules were not. Modules needing writes outside `/run/mayi/pam-auth` and `/run/faillock` may fail under the sandbox; do not widen writable paths without separate review. The upgrade path from 0.4.1-3 only removes the old helper socket when it is a proven-stale socket with the expected legacy owner/group/mode and unchanged inode.

Candidate 0.4.1-4's historical container matrix included Debian 10–13, but Debian 10 is no longer a supported runtime target; this historical result does not establish current platform support. The exact 0.4.1-5 artifact passed the direct-systemd matrix on Debian 11–13 and is **READY FOR INDEPENDENT SECURITY REVIEW**, not production-ready or published. See [`DEBIAN_COMPATIBILITY.md`](DEBIAN_COMPATIBILITY.md), [`AUDIT_REPORT_0.4.1-4.md`](AUDIT_REPORT_0.4.1-4.md), and [`MVP_QUALIFICATION.md`](MVP_QUALIFICATION.md).

## Trust assumptions and non-goals

`SO_PEERCRED` authenticates a kernel-reported OS UID, not a human. The broker, executor, PAM authority, root-owned executable directories, host PAM/NSS configuration, systemd service/cgroup configuration, and system account/group administration are trusted. The published 0.4.1 console-local PAM check is not a protocol authorization boundary; candidate 0.4.1-4's PAM authority is not yet independently audited.

Mayi is broad human-gated root execution, not a command allowlist or semantic safety engine. Approval does not prove that a program, shell, or argument is safe. Execution is at most once, not transactional: a command can partially alter system state before failing or producing an ambiguous result. There is no rollback or child runtime deadline.

Queue and result persistence across broker restart is **NOT CLAIMED**. Queue state/results are in broker memory and are lost on restart; no requests are replayed. The privileged executor's one-shot journal is not durable queue storage.

The filesystem executor is **DISCONNECTED / INCOMPLETE**. Structured filesystem operations remain disabled and are not production functionality. Historical design/qualification records under [`docs/history/filesystem/`](docs/history/filesystem/) do not establish current support.

## Installed identity and release status

The Debian package uses broker UID/GID 23002/23012, requester group `mayi-requester` GID 23011, approver group `mayi-approver` GID 23013, and executor UID 0 / primary GID 23012. Candidate 0.4.1-4's PAM authority uses UID 0/GID 23012 with a `CAP_DAC_READ_SEARCH` capability set. It retains the now-unused legacy `mayi-pam-auth` account from 0.4.1-3 because account name and numeric IDs do not prove package ownership. Package installation does not add human users to role groups. The administrator must check ID collisions and grant only intended memberships. PAM service `/etc/pam.d/mayi-approve` includes host common authentication and account policies.

Published Mayi **0.4.1** remains the stable baseline; its historical artifact SHA-256 is `22409abd977d4d14113ee34e47ed78f94a4e975da84e9606f5fe704116f59ab0`. Candidate **0.4.1-5** passed the supported Debian 11–13 exact-artifact matrix and is **READY FOR INDEPENDENT SECURITY REVIEW**; it is not production-ready, published, or authorized for staging. Candidate 0.4.1-4's old Debian 10–13 results are historical only. Candidate 0.4.1-3's failed positive PAM path is documented in [`AUDIT_REPORT_0.4.1-3.md`](AUDIT_REPORT_0.4.1-3.md). Publication is not deployment. See [`DEBIAN_COMPATIBILITY.md`](DEBIAN_COMPATIBILITY.md) for supported platforms and capabilities.
