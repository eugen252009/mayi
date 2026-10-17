# Debian compatibility and qualification record — Mayi

## Current runtime policy (supersedes historical compatibility claims)

Supported Debian runtime targets are **Debian 11 Bullseye, Debian 12 Bookworm, and Debian 13 Trixie** (`amd64`). Debian 10 Buster is **not supported**. Earlier install, GLIBC, container, or package tests on Debian 10 are historical evidence only; Debian 10 remains an acceptable build environment for a portable GLIBC baseline. Historical release sections below are retained as records, not current support statements.

Runtime support is capability-based, not inferred from a distribution label alone. Mayi 0.4.1-5's enabled path requires Linux Unix-domain sockets with `SO_PEERCRED` and `SCM_RIGHTS`, working local NSS and PAM, systemd service lifecycle/readiness, and the exact `/system.slice/mayi-broker.service` identity used by the PAM authority. The broker runs as UID 23002 with no effective capabilities and `NoNewPrivileges`; the root PAM authority is bounded to `CAP_DAC_READ_SEARCH`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, restricted namespaces/kernel controls, and narrow writable paths. Its PAM stack is part of the trusted computing base. cgroup, peer-UID, NSS/PAM, and state-transition failures are fail-closed.

`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV` is exercised by the disconnected filesystem executor and its confinement tests, but that executor is **DISCONNECTED / INCOMPLETE** and not available in Mayi 0.4.1-5. Therefore `openat2` is not a mandatory capability for the currently enabled runtime path. If filesystem execution is ever enabled, that exact syscall/resolve behavior becomes mandatory; no weaker fallback is acceptable. The PAM helper's `RestrictSUIDSGID=yes` is optional systemd hardening, not a standalone security boundary: `NoNewPrivileges`, its sole `CAP_DAC_READ_SEARCH` capability, the filesystem sandbox, and absence of a command-execution path remain enforced. Debian 10 systemd 241 ignores that directive, so it was not treated as active there; Debian 11–13 systemd enforce it.

## Mayi 0.4.1-5 exact-artifact qualification (direct QEMU systemd guests)

- Exact artifact: `/tmp/mayi-qemu-qualification/artifacts/mayi_0.4.1-5_amd64.deb`, package `mayi 0.4.1-5 amd64`, SHA-256 `cebe101be7cf9f1501ea74949f76ead00bc7e6d593c216ba0a9a6478fa05f381`. The package was not rebuilt or modified during qualification.
- Build provenance: source revision `1da927cc65baf882d557f53e3ddfaf1352dd249f` with 28 dirty/untracked paths; exact source input tar SHA-256 `77e314f0e3d0477089207428e8553e53de3f5634fc12730087f15c37024e6cb1`. Build guest Debian 10, glibc 2.28, GCC 8.3.0, Rust/Cargo 1.95.0, libpam0g-dev 1.3.1-5, TPA CLI 0.6.1. Source diff/status capture is under `/tmp/mayi-qemu-qualification/source-*`.
- Debian 11 Bullseye: kernel `5.10.0-46-amd64`, systemd `247.3-7+deb11u8`. Debian 12 Bookworm: kernel `6.1.0-53-amd64`, systemd `252.39-1~deb12u2`. Debian 13 Trixie: kernel `6.12.111+deb13-amd64`, systemd `257.13-1~deb13u1`.
- All three guests passed fresh install and upgrade from packaged Mayi 0.4.1; all services started. Successful stock PAM authentication, wrong-password rejection, locked-account rejection, initial NSS denial, final NSS denial after PAM, direct protocol approval without a terminal FD (`PAM_AUTH_REQUIRED`, request stayed pending), 300-second challenge expiry, and one-shot/replay checks passed. Helper unavailability was tested by stopping its unit: systemd stopped the `Requires=`-dependent broker as well; restarting the broker restored both. No approval path remained available while the helper was unavailable.
- Two concurrent approval consoles produced exactly one winner on each release. Two concurrent approval consumptions also produced exactly one successful `CONSUMED` result and one `ALREADY_CONSUMED`; the allowed `/usr/bin/true` executor operation succeeded.
- Actual broker/helper/executor service cgroups matched `/system.slice/mayi-{broker,pam-auth,privileged-executor}.service`. The broker was UID 23002/GID 23012, zero effective/permitted/ambient capabilities, `NoNewPrivileges=1`. The PAM authority was UID 0/GID 23012 with only `CAP_DAC_READ_SEARCH` in effective/permitted/bounding/ambient masks and `NoNewPrivileges=1`. Systemd-reported effective PAM sandbox settings included strict filesystem/home protections, private tmp, kernel/control-group restrictions, `RestrictSUIDSGID`, `RestrictNamespaces`, and `LockPersonality`. The separate privileged executor is intentionally UID 0 with broad execution capabilities and `NoNewPrivileges=1`; broad human-gated root execution remains in independent-review scope.
- The guest syscall probe successfully executed `openat2` with all four required resolve flags on each supported kernel. `SO_PEERCRED` was checked by the packaged clients; successful PAM decisions also exercised the broker/helper peer credential and exact cgroup checks. Service stop/start/restart and purge lifecycle checks passed. Purge preserved administrator-created accounts named `mayi-approver` and `mayi-requester`.
- Debian 13 initially reset repeatedly with legacy BIOS firmware; using the same verified image, NoCloud seed, disk, and QEMU arguments with OVMF/UEFI and a writable per-VM variable store booted it successfully. Debian 11 booted with the existing BIOS configuration. No production host configuration or service was changed; no Docker qualification was run.
- Full evidence, logs, and reusable provisioning/test drivers are in `/tmp/mayi-qemu-qualification/QUALIFICATION-STATUS.md` and its `logs/` directory.

**Qualification status: PASS for the requested Debian 11–13 exact-artifact matrix. Candidate status: READY FOR INDEPENDENT SECURITY REVIEW.** This is not production readiness, deployment, publication, or TPA staging authorization. The published 0.4.1 PAM bypass remains a separate production security concern.

The stable published baseline remains 0.4.1, with historical Debian 10–13 test records below. The supported runtime policy above supersedes those historical platform claims.

## Mayi 0.4.1 approval-console UX qualification (2026-09-27)

The exact `mayi 0.4.1 amd64` artifact, SHA-256 `22409abd977d4d14113ee34e47ed78f94a4e975da84e9606f5fe704116f59ab0`, passed fresh-install and 0.4.0-upgrade qualification in disposable Debian 10–13 systemd environments. Bookworm fresh installation used APT on the exact local package. Each environment passed full PAM/auth-before-broker, runtime/queue, installed man-page, conffile, socket, and systemd checks, including 100 executor and 100 broker restarts.

The UX change clears only the visible screen after a fully correlated successful allow/deny/follow-up acknowledgment, and only when stdout is a TTY and `TERM` identifies a supported ANSI-compatible terminal. It does not erase scrollback; failures preserve the request display and report the error. Commands display the actual argv[0] and use separate shell-quoted argument display values. Successful PAM authentication has no interactive success banner/event. PAM behavior, authorization, queue, package dependencies, executor, and filesystem boundaries are unchanged.

The artifact was built with TPA 0.4.0 metadata (`Created-At: 2026-09-27T14:06:03Z`, provenance enabled) from clean source revision `7e7636838507b0399d914741935e9673ed09e710` in disposable Debian 10.13 (glibc 2.28-10+deb10u3, GCC 8.3.0, Rust/Cargo 1.95.0). Both native executables require at most `GLIBC_2.28`. The artifact was not rebuilt after qualification. The 0.4.0 and 0.3.2 artifacts remain byte-for-byte unchanged. No production host access or modification, deployment, or Synology work occurred. Queue persistence remains unclaimed across broker restart; filesystem execution remains disconnected and **INCOMPLETE**. See [MVP_QUALIFICATION.md](MVP_QUALIFICATION.md) for detailed gates and consumer verification.

## Mayi 0.4.0 PAM-authenticated approval qualification (2026-09-27)

The exact `mayi 0.4.0 amd64` artifact, SHA-256 `d0a28d1e0e46837f395bc687b93f76742a91056a33358a5201b5a6ca28946f86`, passed disposable Debian 10–13 systemd qualification. It retains the Debian 10 glibc 2.28 / Python 3.7 floor and adds `libpam0g (>= 1.1.8)` plus `libpam-runtime`. Native executables require at most `GLIBC_2.28`.

Fresh installs and upgrades from 0.3.2 passed on Debian 10, 11, 12, and 13. Trixie additionally passed upgrades from 0.2.0, 0.2.1, 0.2.2, 0.3.0, and 0.3.1. Debian 12 fresh installation used APT on the local package. Each full systemd lifecycle run passed 100 executor and 100 broker restarts. The isolated auth gates verified PAM failure and account/PAM-file denial, same-account and separate requester/approver identities, actual-UID PAM username binding, no broker access/request display before auth, interactive TTY and echo-disabled prompt, rejection of argv/environment/piped-stdin credential channels, process-local auth, and PAM conffile preservation/purge behavior. Runtime, queue, man-page, socket, and systemd checks also passed.

The build used a disposable Debian 10.13 environment with glibc 2.28-10+deb10u3, GCC 8.3.0, and Rust/Cargo 1.95.0. TPA 0.4.0 metadata records `Created-At: 2026-09-27T12:40:21Z`; provenance is enabled. The source tree was dirty and uncommitted; clean-source byte-for-byte reproducibility is not claimed. No publication, deployment, or real-host access/modification occurred. Queue persistence remains unclaimed across broker restart; filesystem execution remains disconnected and **INCOMPLETE**. See [MVP_QUALIFICATION.md](MVP_QUALIFICATION.md) for the complete record.

The packaging-only 0.3.2 artifact was independently tested on Debian 10–13, including fresh installs, 0.3.1 upgrades, installed man-page lookup, and runtime/systemd lifecycle checks; see the 0.3.2 evidence in [MVP_QUALIFICATION.md](MVP_QUALIFICATION.md).

**Historical result (2026-09-26; superseded as runtime policy):** Debian 10 (Buster) was the oldest release tested for the 0.3.1 artifact under the earlier compatibility assumption; Debian 9 (Stretch) was below that package's Python floor. This did not establish current security compatibility. Debian 10 is not supported; use Debian 11–13 subject to the capability requirements above. The administrator later reported manual deployment and smoke testing on the real Debian 12.15 host; this repository qualification/consolidation did not access or modify it.

## Release artifact

- `executor/target/debian/mayi_0.3.1_amd64.deb`
- SHA-256: `9162530d3052389f5b84edef2680e379350bbd79a0981e247628d08a1df1b57e`
- Debian dependencies: `libc6 (>= 2.28)`, `python3 (>= 3.7)`, `adduser`, `init-system-helpers`
- Both native executables (`mayi-executor` and `privileged-executor`) have `GLIBC_2.28` as their highest referenced GLIBC symbol. Their shared-library dependencies resolve on every tested release.
- TPA 0.4.0, provenance enabled; `Created-At: 2026-09-26T22:11:16Z`.
- Built in a disposable Debian 10 environment: glibc 2.28, Python 3.7.3, GCC 8.3.0, Rust/Cargo 1.95.0. Buster's archived apt sources were pinned to the 2024-06-12 Debian snapshot. No libc or other runtime package was force-installed or substituted.
- Source tree was dirty and uncommitted; this artifact is not claimed reproducible from a clean revision. The 0.3.0 package was not overwritten: its SHA-256 remains `0f356c880d8351f9ca5a05267530b8b9741a08b6b715ee0c9d1fe571ac851e57`.

## Compatibility matrix

The exact 0.3.1 `.deb` above was used throughout; each disposable runtime used systemd as PID 1, a private cgroup namespace, no host mounts, and no runtime network. Fresh installs ran the installed synchronous and queue/approval flow, authorization and UID-binding checks, one-shot/replay and concurrency checks, dependency DAG and failure-blocking cases, socket/security regressions, systemd lifecycle, and 100 executor plus 100 broker restarts. All reported checks passed.

| Debian | Runtime baseline in test image | Result |
| --- | --- | --- |
| 10 Buster | glibc 2.28-10+deb10u3; Python 3.7.3; systemd 241-7~deb10u10 | Fresh 0.3.1 install and full functional/security/systemd lifecycle qualification PASS; 100/100 restarts each PASS. This is the oldest technical baseline tested. |
| 11 Bullseye | glibc 2.31-13+deb11u14; Python 3.9.2; systemd 247.3-7+deb11u8 | Same artifact; full qualification PASS; 100/100 restarts each PASS. |
| 12 Bookworm | glibc 2.36-9+deb12u14; Python 3.11.2; systemd 252.39-1~deb12u2 | Same artifact; full qualification PASS; 100/100 restarts each PASS. A separate `apt-get install /root/mayi_0.3.1_amd64.deb` smoke install activated both services. This glibc version matches the version reported for the real Debian 12.15 host; the administrator separately reported a successful manual deployment and smoke test there. |
| 13 Trixie | glibc 2.41; Python 3.13; systemd 257.13 | Fresh install, queue/systemd qualification, and upgrades from 0.2.0, 0.2.1, 0.2.2, and 0.3.0 PASS. Each lifecycle suite passed 100/100 executor and broker restarts. |

Debian 9 Stretch was checked without bypassing package dependencies: its archived baseline has glibc 2.24 and Python 3.5.3, while the package correctly requires Python >=3.7. Debian's Stretch `python3` therefore cannot satisfy the package dependency. No forced install or unsupported-Python workaround was attempted. This establishes the next older release as a concrete package/runtime prerequisite boundary; it is not a claim that Python alone explains every possible Stretch incompatibility.

## Upgrade and prior-artifact notes

The 0.3.1 upgrade from 0.3.0 was functionally qualified on Debian 13, where the old package is installable. The 0.3.0 package cannot be installed normally on Debian 10–12: it declares `libc6 (>= 2.39)`, and its privileged executor actually references `GLIBC_2.39` (the old broker binary's maximum is `GLIBC_2.34`). Thus no 0.3.0 upgrade was possible on those older test images without bypassing a genuine runtime requirement. Do not force-install the old artifact. The new 0.3.1 package is a fresh install on Debian 10–12; the tested Debian 13 upgrade preserves memberships and legacy accounts.

## Scope and limits

- These were disposable containers sharing the runner's Linux kernel; Debian-specific kernels were not booted. The active command path relies on established Linux facilities such as Unix-domain sockets/`SO_PEERCRED` and systemd notify/readiness. Kernel-version compatibility was not independently boot-tested. The filesystem executor remains disconnected and **INCOMPLETE**.
- This work changes compatibility declarations and Python syntax/runtime compatibility only; it does not weaken role authorization, exact broker-UID authentication, exact executable/argv binding, synchronous approval, one-shot execution, dependency enforcement, or fail-closed socket recovery. Queue/results remain in-memory across broker restarts.
- The disposable qualification did not perform a real-host installation or operation. The administrator subsequently reported manual deployment, both services active, and successful queued dependency/approval/privileged-execution/`--wait --fail=0` smoke testing on Debian 12.15. This consolidation did not access or modify the host. No live filesystem mutation was reported.
