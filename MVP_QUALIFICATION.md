# Mayi package and deployment qualification record

## Debian portability / package 0.3.1 release (2026-09-26)

### Result

Debian 10 (Buster) is the oldest technically compatible Debian release tested for the 0.3.1 package: it was built against glibc 2.28 and Python 3.7.3, then the identical artifact passed fresh-install functional, security, and systemd lifecycle qualification on Debian 10, 11, 12, and 13. Debian 9 (Stretch) is below the Python dependency floor (3.5.3 versus >=3.7); no dependency bypass was attempted. Debian 10 is EOL, so this technical floor must not be confused with a recommendation to run an unsupported OS. Full versions, hashes, matrix, upgrade scope, kernel limitations, and EOL caveats are in [DEBIAN_COMPATIBILITY.md](DEBIAN_COMPATIBILITY.md).

The 0.3.0-to-0.3.1 upgrade passed on Debian 13. The 0.3.0 package requires and actually uses GLIBC_2.39 in its privileged executor, so it was not upgrade-installable on Debian 10–12 without bypassing a genuine runtime requirement. The final 0.3.1 native executables require at most GLIBC_2.28; the package declares `libc6 (>= 2.28)` and `python3 (>= 3.7)`. The administrator subsequently reported manual installation and successful queue/dependency/human-approval/privileged-execution/`--wait --fail=0` smoke testing on the real Debian 12.15 host. This consolidation did not access or modify the host. The original 0.3.0 artifact and hash remain unchanged.

### Artifact and build

- Package: `executor/target/debian/mayi_0.3.1_amd64.deb`
- SHA-256: `9162530d3052389f5b84edef2680e379350bbd79a0981e247628d08a1df1b57e`
- TPA 0.4.0; provenance enabled; `Created-At`: 2026-09-26T22:11:16Z
- Build baseline: Debian 10 (Buster), glibc 2.28-10+deb10u3, Python 3.7.3, GCC 8.3.0, Rust/Cargo 1.95.0; archived apt sources pinned to the 2024-06-12 snapshot.
- Dirty, uncommitted working tree; no clean-source reproducibility claim. No commit was created.

### Matrix summary

| Debian | Result |
| --- | --- |
| 10 Buster | Fresh install and full installed/security/systemd lifecycle qualification PASS; 100/100 executor and broker restarts. |
| 11 Bullseye | Same artifact and gates PASS; 100/100 restarts each. |
| 12 Bookworm | Same artifact and gates PASS on glibc 2.36-9+deb12u14; separate local apt install activated both services. Administrator later reported a successful manual deployment/smoke test on the real Debian 12.15 host. |
| 13 Trixie | Fresh install and upgrades from 0.2.0, 0.2.1, 0.2.2, and 0.3.0 PASS; full lifecycle and 100/100 restart gates PASS. |
| 9 Stretch | Not installable without violating the declared Python >=3.7 dependency (Stretch provides Python 3.5.3); no forced install. |

Disposable systemd containers shared the runner's kernel; Debian release kernels were not booted. The administrator subsequently reported real-host smoke testing; this consolidation did not access or modify the host. Filesystem execution remains disconnected and **INCOMPLETE**. Queue/results remain in-memory.

## Protocol 5 / package 0.3.0 asynchronous queue release (2026-09-26)

### Result

Mayi 0.3.0 adds asynchronous broker-generated request IDs, immutable exact executable/argv queue entries, same-requester dependencies, cycle checking, dependency-aware one-shot execution, `--wait`/`--status` failure-budget observation, and a persistent approval console. The existing synchronous exact-command flow remains enabled. Queue state and results are in memory only; broker restart invalidates them, and no restart-safe queue retention or replay is claimed. The filesystem executor remains disconnected and **INCOMPLETE**.

Final qualification is performed by `python3 executor/package/qualify-systemd.py` in disposable Debian 13 containers with systemd PID 1. The gate covers a fresh install and upgrades from 0.2.0, 0.2.1, and 0.2.2, alongside the package lifecycle/socket suite. Its installed CLI qualification checks unique IDs and ID-only stdout, immediate queue return, cross-requester dependency rejection, unknown IDs, linear and branching DAGs, exact job order and one-shot executor starts, failed/denied/follow-up transitive blocking, partial/numeric approval, skipped-set resurfacing, failure budgets, fail-instant without cancellation, `--status`, and existing synchronous y/n/e regressions. PTY unit tests cover branching display, partial approval, skip resurfacing, automatic arrival display, persistent operation, exact argv, and decisions. See test records below.

No real-host install, systemctl action, nginx command, privileged host command, or filesystem mutation was performed. Disposable containers/image were removed after successful qualification.

### Artifact and source state

- Package: `executor/target/debian/mayi_0.3.0_amd64.deb`
- SHA-256: `0f356c880d8351f9ca5a05267530b8b9741a08b6b715ee0c9d1fe571ac851e57`
- TPA: `0.4.0`; `Created-At`: `2026-09-26T19:59:26Z`; provenance enabled
- Runtime dependencies: `adduser`, `init-system-helpers`, `libc6 (>= 2.39)`, `python3`
- Upgrade baselines: 0.2.0 `685632ff860e1efe1a55adf7af99b3d82446755875936d3aa8bf5e978635ef9d`; 0.2.1 `1799e555c6e983b99b10e3c92d52b46079b2b9fa853618c424c317ebc12316dd`; 0.2.2 `24b5d51daf274290af2ee73df3393be70ce588567a0608cd7a571ec4f9f35f58`.
- Base revision: `a593e6920551b52e9eef4565e1752c1c8f6593e6`; working tree was dirty/uncommitted at build. Clean-source reproducibility is not claimed.

### Qualification record

| Gate | Result |
| --- | --- |
| Rust unit tests (main broker/executor and privileged executor) | PASS — 71 + 5 |
| Python suite | PASS — 58 |
| Clippy with warnings denied, Rust format, Python compile, `git diff --check` | PASS |
| Fresh 0.3.0 install; upgrades from 0.2.0, 0.2.1, 0.2.2 | PASS |
| Injected mandatory package account/group setup failure | PASS — configuration fails closed |
| Queue IDs, asynchronous submission, ownership and unknown dependency checks | PASS |
| Linear success chain and branching DAG with two prerequisites | PASS — child starts only after all parents succeed |
| Failed and denied dependency chains | PASS — descendants blocked; no executor starts |
| Partial approval, typed `210` ordering, follow-up, skip/resurface | PASS |
| `--wait` failure budgets 0/1 and `--fail-instant` without cancellation; `--status` | PASS |
| Persistent console PTY: branch display, arrivals, partial selection, skip, aliases | PASS |
| Existing synchronous approve/deny/explain, exact argv, replay, cross-requester binding | PASS |
| Fresh package units, upgrade memberships/legacy accounts, systemd readiness/lifecycle | PASS |
| Socket attack/recovery matrix, competing starts, 100 executor + 100 broker restarts per environment | PASS |
| Real-host installation/service operation/nginx/filesystem execution | NOT PERFORMED — administrator authorization required |
| Filesystem executor | **INCOMPLETE / DISCONNECTED** |

The artifact was built from the dirty source tree identified above and then installed/qualified; subsequent qualification-script and documentation edits do not alter the packaged executable/client implementation. No commit was created.

---

## Protocol 5 / package 0.2.2 systemd upgrade and socket recovery (2026-09-26)

### Result

All requested implementation gates passed in disposable Debian 13 containers running systemd as PID 1. Fresh 0.2.2 install, upgrades from 0.2.0 and 0.2.1, failed package-configuration injection, old-unit replacement, normal systemd lifecycle, 100 executor and broker restarts, competing starts, real SIGKILL stale-socket recovery, socket attack cases, NSS role mapping, broker-UID executor authentication, and y/n/e regressions passed. No real-host operation was performed. The filesystem executor remains disconnected and **INCOMPLETE**.

### Artifact and source state

- Package: `executor/target/debian/mayi_0.2.2_amd64.deb`
- TPA: `0.4.0`; `Created-At`: `2026-09-26T18:59:31Z`; provenance enabled
- SHA-256: `24b5d51daf274290af2ee73df3393be70ce588567a0608cd7a571ec4f9f35f58`
- Runtime dependencies: `adduser`, `init-system-helpers`, `libc6 (>= 2.39)`, `python3`
- Retained upgrade baselines: 0.2.0 SHA-256 `685632ff860e1efe1a55adf7af99b3d82446755875936d3aa8bf5e978635ef9d`; 0.2.1 SHA-256 `1799e555c6e983b99b10e3c92d52b46079b2b9fa853618c424c317ebc12316dd`.
- Base revision: `a593e6920551b52e9eef4565e1752c1c8f6593e6`; working tree dirty/uncommitted at build time. No reproducibility from a clean commit is claimed.

### Root causes and repairs

- **Invalid group command:** Debian `addgroup USER GROUP` is not the user-to-group operation. The old script suppressed those failures with `|| true`. 0.2.2 uses idempotent membership checks followed by `adduser --quiet USER GROUP`; mandatory account/group/membership and service setup failures now fail `postinst`.
- **Stale systemd configuration/lifecycle:** old prerm scripts stopped both services even on upgrade; old postinst did not explicitly reload changed units and used `start`, which cannot refresh an already-active process. The new prerm leaves active services alone on future upgrades; because an older installed prerm may already have stopped them, the new postinst reloads systemd, restarts the executor (also starts it if stopped), then starts the broker after readiness. Debian policy is respected via `deb-systemd-invoke`.
- **Executor `AddrInUse`:** the old executor had no SIGTERM cleanup and refused any pre-existing pathname; closing a Unix listener does not remove its filesystem socket. 0.2.2 cleans its own socket inode on graceful stop and safely recovers a crash-left stale socket at startup. SIGKILL still leaves the path, intentionally covered by startup recovery.
- **Broker sockets:** the prior broker startup removed a same-owner socket after any failed connect and lacked competing-start serialization/clean-stop cleanup. It now reclaims only an expected-owned socket whose nonblocking connect probe returns `ECONNREFUSED`, serializes both endpoints with a lock, and removes only its own socket inodes on graceful stop.

### Systemd-running qualification

`executor/package/qualify-systemd.py` built a Debian 13 (`debian:trixie`, systemd 257.13) image and exercised fresh, 0.2.0-upgrade, and 0.2.1-upgrade containers with systemd PID 1. Runtime containers had private cgroup namespaces, no host mounts, no runtime network, and were removed. They were privileged only to run systemd. Package files/services and all fixture effects remained inside those disposable containers.

| Gate | Result |
| --- | --- |
| Fresh install 0.2.2, units reloaded/loaded, executor and broker active | PASS |
| 0.2.0→0.2.2 and 0.2.1→0.2.2 upgrades while both old services are active; old executor socket inode replaced and new readiness event observed | PASS |
| Invalid `addgroup` output on target upgrade | NONE |
| Human role-group memberships and pre-existing legacy accounts preserved | PASS |
| Wrong-GID account setup injection makes dpkg configuration fail | PASS |
| New `ExecStart`, no obsolete requester/approver UID flags, executor `Type=notify` loaded | PASS |
| Runtime ownership/modes: request `mayi-broker:mayi-requester 0750`; approval `mayi-broker:mayi-approver 0750`; executor dir `root:mayi-broker-socket 0750`; executor socket same group `0660` | PASS |
| Executor `Requires`/`After` readiness gates broker startup | PASS |
| Systemd clean stop/start and restart; 100/100 executor plus broker restarts in each environment | PASS |
| Simultaneous executor starts: exactly one process/listener succeeds | PASS |
| Absent socket, actual stale bound-then-closed socket, SIGKILL recovery | PASS |
| Live foreign socket, unexpected-owner stale socket, symlink, regular file, directory | PASS — each preserved/rejected as appropriate |
| Broker clean stop/start, SIGKILL auto-restart from two crash-left sockets, independent stale request/approval recovery | PASS |
| Broker rejects live foreign request/approval sockets and preserves symlink, regular-file, and directory replacements | PASS |
| Full installed requester/approver role and y/n/e regression, execution failure, argv/environment, consume/replay tests | PASS |

Stale recovery is restricted to `/run/mayi/executor/executor.sock`. Startup uses no-follow metadata, requires a socket owned by root:GID 23012, mode `0660`, link count 1, and treats only `ECONNREFUSED` as proof of staleness. It rechecks device/inode before unlink. A live listener or any ambiguous state fails closed. A root-owned `0750` parent prevents role-group users from replacing entries. No sibling cleanup occurs. The broker applies corresponding checks and a single-instance lock to its request/approval endpoints.

No real-host install, systemctl action, privileged command, nginx operation, or host filesystem mutation was performed. The package is qualified for administrator review, not deployed. The filesystem executor remains disconnected and **INCOMPLETE**.

## Earlier Protocol 5 / package 0.2.1 NSS role authorization

This section records the earlier group-authorization release; its then-unqualified systemd statements are superseded by the 0.2.2 qualification above.

### Result

The requester/approver role authorization change passed Rust, Python, package, and disposable Debian 13 Docker qualification. Fresh 0.2.1 install and 0.2.0→0.2.1 upgrade both passed the real CLI → broker → PTY approval console → privileged executor flow. No real-host deployment was attempted. Systemd-managed startup was not exercised. The filesystem executor remains disconnected and **INCOMPLETE**.

### Artifact

- Package: `executor/target/debian/mayi_0.2.1_amd64.deb`
- TPA: `0.4.0`; `Created-At`: `2026-09-26T17:21:06Z`
- SHA-256: `1799e555c6e983b99b10e3c92d52b46079b2b9fa853618c424c317ebc12316dd`
- Runtime dependency: `libc6 (>= 2.39)`; Docker image: `debian:trixie`
- Upgrade baseline `mayi_0.2.0_amd64.deb` SHA-256: `685632ff860e1efe1a55adf7af99b3d82446755875936d3aa8bf5e978635ef9d` (verified by the qualification script).
- The source tree was dirty and uncommitted at build time; this artifact is not claimed reproducible from a clean commit.

### Qualification

`executor/package/qualify-mvp.sh` ran two isolated containers (fresh install and 0.2.0 upgrade). Each had no host mounts, Docker socket, or privileged mode. Networking was disconnected and verified absent before Mayi processes started. Both containers were removed after qualification.

| Gate | Result |
| --- | --- |
| Rust tests (`cargo test --locked --all-targets`) | PASS — 66 broker/main tests and 3 privileged-executor tests |
| Python tests (`pytest`) | PASS — 64 |
| Clippy (`--all-targets -- -D warnings`), formatting, shell/Python syntax, `git diff --check` | PASS |
| New 0.2.1 package build and Debian metadata | PASS |
| Fresh 0.2.1 installation (no fixed requester/approver accounts) and 0.2.0→0.2.1 apt upgrade | PASS |
| Human role-group memberships preserved during upgrade and purge; human accounts not deleted | PASS |
| Supplementary requester, approver, both-role, unauthorized, and primary-GID role memberships | PASS |
| Unauthorized role attempts return clear authorization errors; supplied socket GID alone does not authorize | PASS |
| Actual requester UID binding, actual approver/view UID binding, and cross-requester consume denial | PASS |
| Same UID in both role groups can request and approve | PASS |
| Approve, deny (exit 10), explain (exit 20), execution failure (exit 14) | PASS |
| Literal metacharacter argv, sanitized child environment, immutable executable/argv, one-shot and concurrent consume | PASS |
| Direct executor access denied to requester/approver; executor accepts only exact broker UID | PASS |
| Broker restart invalidation and executor replay protection | PASS |
| Package purge preserves human users/memberships | PASS |
| Filesystem executor handoff | NOT ENABLED; **INCOMPLETE** |

Fresh 0.2.1 installs create no fixed requester/approver users. The upgrade intentionally leaves legacy 0.2.0 non-login accounts in place; they have no special authority apart from group membership. The qualification uses harmless commands inside the containers. No host command, package installation, service action, filesystem mutation, or executor action was performed. This record does not qualify host systemd startup or host first use.

## Earlier Protocol 5 / package 0.2.0 qualification

This historical section records the prior 0.2.0 qualification. Its UID-based role setup and “upgrade not covered” statements are superseded by the 0.2.1 record above.

### Artifact provenance

- Package: `mayi_0.2.0_amd64.deb`
- TPA: `0.4.0`, provenance enabled
- `Created-At`: `2026-09-26T16:02:39Z`
- SHA-256: `685632ff860e1efe1a55adf7af99b3d82446755875936d3aa8bf5e978635ef9d`
- Runtime dependency: `libc6 (>= 2.39)`; qualification image `debian:trixie`

The 0.2.0 package was installed, reinstalled, used, and purged in a disposable Debian 13 container. It did not run systemd as PID 1. No host privileged action or live filesystem mutation occurred.
