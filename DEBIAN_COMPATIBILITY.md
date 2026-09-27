# Debian compatibility qualification — Mayi 0.3.1

**Result (2026-09-26):** Debian 10 (Buster) is the oldest technically compatible Debian release tested. Debian 9 (Stretch) is below the package's Python floor. This is a technical compatibility result, not a recommendation to operate an end-of-life OS: Debian 10 LTS ended in June 2024, and Debian 11 LTS ended on 2026-08-31. For a currently maintained Debian OS, use Debian 12 or newer. The administrator later reported manual deployment and smoke testing on the real Debian 12.15 host; this repository qualification/consolidation did not access or modify it.

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
