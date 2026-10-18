# Mayi 0.4.1-4 PAM-boundary candidate report

**Status: exact-artifact Debian qualification matrix PASS; release qualification is still pending independent security review.** Candidate `0.4.1-4` is **NOT independently audited, NOT release-qualified, NOT production-ready, and NOT published**. Do not stage or distribute it.

## Scope and artifact identity

- Candidate: `mayi 0.4.1-4 amd64`
- Exact artifact: `executor/target/debian/mayi_0.4.1-4_amd64.deb`
- SHA-256: `0289b3c0bb5f43680a97574ca46f062004992ba71abc74d3d94ce2b6a5e42287`
- Package identity/architecture: `mayi`, `0.4.1-4`, `amd64`
- Build: disposable Debian 10/Buster, glibc 2.28, GCC 8.3.0, Rust/Cargo 1.95.0, `libpam0g-dev` 1.3.1-5, TPA CLI 0.6.1. Both native binaries require at most `GLIBC_2.28`.
- A separate SHA-256 calculation matched `sha256sum`; extracted package payload matched the final build staging tree. The package was not rebuilt after exact-artifact qualification.
- The retained `0.4.1-2` artifact remains unchanged (`4322f6689a76d374511cce53d3ae2315b93859638f01b768b4a09173cfd9722d`). The blocked `0.4.1-3` artifact also remains unchanged (`3c233aae39fc3c763d7ddbaa1c0d73906ec07ac5705e966aaac2b3b16f332802`). Neither was staged or published.

## Approval and PAM authority boundary

The earlier unprivileged helper (`0.4.1-3`) could not authenticate a different UID under Debian's stock `common-auth`/`pam_unix`: `unix_chkpwd` reported `check pass; user unknown`. That exact positive-path failure is recorded in [`AUDIT_REPORT_0.4.1-3.md`](AUDIT_REPORT_0.4.1-3.md). The `0.4.1-4` implementation uses a narrowly scoped root-owned PAM authority; it does not weaken PAM or accept group membership as a substitute for authentication.

- The broker remains unprivileged at UID/GID 23002/23012. It authenticates socket peers with `SO_PEERCRED`, checks the actual peer UID against NSS approver-group membership, validates an active unexpired view before authentication, and rechecks group membership and decision state under its lock after PAM succeeds.
- A decision transports exactly one controlling-terminal descriptor to the broker using `SCM_RIGHTS`. Rust sends the broker-derived UID and correlated operation/challenge/digest/view tuple to `/run/mayi/pam-auth/auth.sock`. No client-supplied username, password, reusable PAM assertion, or session token is trusted.
- The PAM service runs with UID 0 and GID 23012 because Debian `pam_unix` needs a privileged authority to authenticate another local UID. Its systemd unit bounds all capability sets to `CAP_DAC_READ_SEARCH`, sets `NoNewPrivileges=yes`, restricts namespaces and address families, uses `ProtectSystem=strict` and `ProtectHome=read-only`, and grants writable paths only for the PAM socket and `/run/faillock`. It does not receive Mayi approval state and has no command-execution path. This is still a privileged component and is a primary target for independent review; it is not an unprivileged helper and must not be described as one.
- The helper accepts peers only when kernel credentials show broker UID 23002 **and** `/proc/<pid>/cgroup` places the process in the root-managed `/system.slice/mayi-broker.service` cgroup. It deliberately does not inspect `/proc/<pid>/exe`: the helper lacks `CAP_SYS_PTRACE`, and cross-UID executable inspection is ptrace-gated. An out-of-cgroup process running as UID 23002 was tested and rejected. The systemd unit/cgroup path is fixed; non-systemd operation or a renamed/moved broker unit fails closed and is not qualified. Host root/systemd administration and the broker service are trusted.
- PAM resolves the username from the broker-derived UID, calls the configured `mayi-approve` PAM stack including account management, supports echo-on/echo-off prompts, bounds authentication to 300 seconds, and limits failed attempts to five per UID per 10-minute window in helper memory. A helper restart resets this in-memory throttle; it is an online-abuse control, not a durable account lockout. Only the stock local Debian PAM stack was end-to-end qualified; third-party MFA/SSSD/custom modules were not. PAM modules that require writes outside `/run/mayi/pam-auth` and `/run/faillock` may fail under the unit's filesystem sandbox; do not widen writable paths without a separate security review.
- Upgrade from `0.4.1-3` stops the old helper, removes its legacy UID 23003 account, and safely reclaims only the exact old helper socket when it is a stale socket with the expected legacy owner/group/mode and unchanged inode. A live or ambiguous socket remains fail-closed.

## Exact-artifact qualification evidence

The final artifact hash was pinned in `executor/package/qualify-systemd.py`. The full fresh-install, upgrade, PAM, package, queue, and systemd lifecycle matrix passed on disposable systemd containers for Debian 10–13. The tested upgrade baselines were 0.4.0, 0.4.1, 0.4.1-1, 0.4.1-2, and 0.4.1-3 as applicable in the harness; every release suite included the explicit 0.4.1-3 to 0.4.1-4 migration.

| Debian | Exact-artifact result |
| --- | --- |
| 10 Buster | Fresh install, upgrades, PAM/adversarial suite, package setup failure gate, and systemd lifecycle PASS. |
| 11 Bullseye | Fresh install, upgrades, PAM/adversarial suite, package setup failure gate, and systemd lifecycle PASS. |
| 12 Bookworm | Fresh install, upgrades, PAM/adversarial suite, package setup failure gate, and systemd lifecycle PASS. |
| 13 Trixie | Fresh install, upgrades, PAM/adversarial suite, package setup failure gate, and systemd lifecycle PASS. |

PAM/boundary cases exercised against the installed package included raw decision without a terminal FD, forged identity fields, direct same-UID helper access outside the broker cgroup, failed and locked credentials, unauthorized UID socket-DAC rejection, helper unavailability, role removal during the PAM prompt, direct Rust approval, cross-UID view transfer, one-shot replay, broker restart invalidation, concurrent decisions, and per-UID failed-attempt throttling. The suite also ran 100 executor restarts, 100 broker restarts, and 10 PAM-helper/broker restarts per lifecycle environment. The upgrade migration from the 0.4.1-3 unprivileged service/account passed on all four suites.

Repository validation on the final implementation: 82 Rust main tests and 5 privileged-executor tests passed; Python tests passed (52 passed, 9 skipped); Clippy with `-D warnings`, formatting, Python/shell syntax, and `git diff --check` passed. The full package qualification is stronger than unit evidence but is not a substitute for independent review.

## Audit readiness, residual limits, and handling

The candidate is ready for **independent source and exact-artifact review**, not for deployment or publication. Review should specifically challenge capability confinement, PAM lifecycle/error handling, cgroup peer identity and systemd assumptions, terminal-FD transfer, decision-state revalidation, legacy socket migration, and the package maintainer scripts. The candidate was built from a working-tree source snapshot; no clean-commit/reproducible-build claim is made. The source and package inputs are available in the repository, and the build snapshot used for the final artifact remains at `/tmp/mayi-release-0.4.1-4f/src` on this machine.

Published Mayi 0.4.1 still has a console-local PAM gate that a direct approval-socket client can bypass. The 0.4.1-2 artifact is deliberately unchanged and unpublished; candidate 0.4.1-4 does not retroactively change that release. Filesystem execution remains **DISCONNECTED / INCOMPLETE** and was not enabled. No production service was stopped or restarted, no host system file was changed, no real-root executor was enabled, and no artifact was staged or published through TPA.run. Queue/result persistence across broker restart remains **NOT CLAIMED**.
