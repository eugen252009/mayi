# Mayi 0.4.1-3 approval-boundary audit report

**Status: BLOCKED — NOT QUALIFIED, NOT PRODUCTION-READY, NOT PUBLISHED.** This is an implementation and test report, not the required independent security review. Do not stage or distribute the candidate.

## Scope and artifact identity

- Candidate: `mayi 0.4.1-3 amd64`
- Artifact: `executor/target/debian/mayi_0.4.1-3_amd64.deb`
- SHA-256: `3c233aae39fc3c763d7ddbaa1c0d73906ec07ac5705e966aaac2b3b16f332802`
- Build: disposable Debian 10 (Buster), glibc 2.28, GCC 8.3.0, Rust/Cargo 1.95.0, TPA 0.6.1. Both packaged executables require at most `GLIBC_2.28`.
- Exact-artifact checks performed: package identity and architecture inspected; packaged native executables match the candidate build outputs; maintainer scripts, systemd units, tmpfiles, and PAM policy match their packaging inputs.
- The retained `0.4.1-2` artifact remains unchanged: SHA-256 `4322f6689a76d374511cce53d3ae2315b93859638f01b768b4a09173cfd9722d`.

## Proposed boundary change

Each approval decision transports one terminal descriptor to the broker via `SCM_RIGHTS`. Rust checks the peer's NSS approver-group membership, sends a correlated request to a separate PAM helper, and rechecks group membership under broker state lock after PAM succeeds. The helper authenticates the broker-derived UID through `/etc/pam.d/mayi-approve`, including account management. There is no reusable client assertion or PAM session. Decision-without-descriptor and direct raw approval requests are intended to fail closed. Filesystem execution remains disconnected and disabled.

The candidate currently runs this helper as unprivileged UID 23003. This does **not** work with the stock Debian `common-auth`/`pam_unix` policy when authenticating a different UID.

## Blocking finding: stock PAM cannot authenticate the peer from the unprivileged helper

The exact candidate was installed in a disposable, network-disabled Debian Trixie systemd container with no host mounts. Package installation, unit topology, installed man pages, and package metadata checks passed. The first valid approval through the packaged console then failed despite supplying the correct account password:

```text
unix_chkpwd: check pass; user unknown
pam_unix(mayi-approve:auth): authentication failure; ... uid=23003 euid=23003 ... user=mayi-approver-only
PAM_AUTHENTICATION_FAILED
```

On Debian, `unix_chkpwd` intentionally prevents an unprivileged caller from checking another account's password. The package's helper is UID 23003, while the authenticated approver is a different UID. Therefore the current candidate cannot complete the required positive authentication path under the included stock PAM policy. The Debian 10–13 qualification run stopped at this first decision and did not complete the matrix.

A normal PAM stack that authenticates arbitrary local peer accounts requires a privileged PAM authority (typically root) or a specifically configured authentication backend that supports this operation without root. The present request also forbids enabling real-root behavior, setuid, capabilities, and host-file changes. I have **not** changed the helper to root, weakened PAM policy, or otherwise worked around this constraint. An explicit decision is needed before implementation continues:

1. authorize a narrowly scoped, independently reviewed privileged PAM helper that authenticates only broker-originated requests and never executes requester-selected commands; or
2. specify an acceptable, broker-verifiable PAM backend that can authenticate arbitrary approver UIDs from an unprivileged service and qualify its behavior on supported Debian releases.

Until then, the approval bypass is not resolved in a usable release candidate.

## Tests and checks completed

- Rust: 80 main/broker/PAM/filesystem tests and 5 privileged-executor tests passed. This covers strict decision framing/FD handling, PAM text sanitization, secret clearing, multi-prompt echo-off/echo-on behavior, and terminal restoration on catchable signals.
- Python: 52 passed, 9 skipped outside package qualification.
- Clippy (`-D warnings`), formatting, Python syntax, and `git diff --check` passed.
- A Debian Trixie disposable systemd install passed basic package, metadata, and service-topology checks before the valid PAM decision failed.
- Not completed: Debian 10–13 exact-package qualification; upgrade qualification; success/failure/locked-account end-to-end matrix; concurrent, stale/replay, and restart qualification against a working PAM helper; full exact-artifact boundary re-audit.

## Publication, deployment, and isolation

No candidate was staged or published through TPA.run. No production Mayi service was stopped or restarted, no host system file was modified, and no real-root executor or filesystem mutation was enabled. The disposable qualification container was removed. Queue/result persistence across broker restart remains **NOT CLAIMED**; filesystem execution remains **DISCONNECTED / INCOMPLETE**.

## Required next steps

1. Resolve the privileged-PAM-helper constraint above; do not weaken the authentication requirement or make a client assertion authoritative.
2. Fix the positive PAM path and rerun all adversarial and integration tests, including the distinct-UID group-removal-during-prompt case.
3. Rebuild a new candidate identity if any bytes change; qualify the exact artifact on Debian 10–13 and from the specified upgrade baselines.
4. Obtain an independent audit of the final source and exact qualified artifact. Do not publish or call the release production-ready before that review passes.
