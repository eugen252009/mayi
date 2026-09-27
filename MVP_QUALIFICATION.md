# Mayi package and deployment qualification record

## Approval-console UX refresh — package 0.4.1 (2026-09-27)

### Scope

Mayi 0.4.1 is a console-only presentation update. After a fully correlated broker acknowledgment for allow, deny, or follow-up, `mayi-approve` clears the visible screen using ANSI clear-display/home sequences only when stdout is a TTY and `TERM` identifies a supported ANSI-compatible terminal; it never sends the scrollback erase sequence. Rejected or errored decisions preserve the current display and report the error. The console renders the executable and actual argv[0] on the command line, then each remaining argument on its own shell-quoted display line, with JSON escaping for values that cannot be represented safely as a compact literal. This is display notation, not shell input. Successful authentication proceeds directly to the console without an `Authenticated.` banner or auth-success event in interactive output.

No PAM policy, authentication behavior, role checks, broker authorization/approval semantics, queue behavior, package dependencies, executor behavior, or filesystem boundary changed. Queue/results persistence across broker restart remains **NOT CLAIMED**. The filesystem executor remains **DISCONNECTED / INCOMPLETE**.

### Exact artifact and build provenance

- Package: `executor/target/debian/mayi_0.4.1_amd64.deb` (`mayi 0.4.1 amd64`)
- SHA-256: `22409abd977d4d14113ee34e47ed78f94a4e975da84e9606f5fe704116f59ab0`
- Dependencies: unchanged from 0.4.0, including `libpam0g (>= 1.1.8)` and `libpam-runtime`.
- TPA metadata: version 0.4.0, `Created-At: 2026-09-27T14:06:03Z`; provenance enabled.
- Built in disposable Debian 10.13 (Buster), glibc `2.28-10+deb10u3`, GCC 8.3.0, Rust/Cargo 1.95.0; both native executables require at most `GLIBC_2.28`.
- Builder source revision: `7e7636838507b0399d914741935e9673ed09e710`; source was clean. The artifact was not rebuilt after qualification. 0.4.0 (`d0a28d1e…`) and 0.3.2 (`f5e81423…`) artifacts remain unchanged.

### Exact-artifact qualification

`executor/package/qualify-systemd.py` pinned the package SHA-256 before each disposable Debian suite. Fresh installs and upgrades from 0.4.0 passed on Debian 10–13. Bookworm fresh installation used `apt-get install` on the exact local `.deb`. Each fresh/upgrade lifecycle environment passed the installed-man-page, PAM, auth-before-broker, runtime/queue, socket, conffile, and systemd checks, including 100 executor and 100 broker restarts.

| Debian | Result |
| --- | --- |
| 10 Buster | Fresh 0.4.1 install and 0.4.0 upgrade; full PAM, runtime/queue, man-page, conffile, socket, and systemd qualification PASS. |
| 11 Bullseye | Fresh 0.4.1 install and 0.4.0 upgrade; all qualification gates PASS. |
| 12 Bookworm | Fresh APT install of local 0.4.1 and 0.4.0 upgrade; all gates PASS. |
| 13 Trixie | Fresh 0.4.1 install and 0.4.0 upgrade; all gates PASS. |

Focused gates verified allow/deny/follow-up clearing only after success, no clear on errors, no scrollback erase, no clear for non-TTY/dumb/unknown terminals, and a newly arriving request rendered after the prior successful decision cleared the old screen. PAM success produced no authentication banner or success event; wrong-password, account/PAM policy, TTY, argv/environment/piped-stdin, and pre-broker visibility restrictions remained passing. Rust tests: 77 + 5; Python tests: 51 passed, 9 skipped; Clippy with warnings denied, formatting, Python syntax, man rendering, and diff checks passed.

No production host was accessed or modified; no deployment or Synology work occurred. Publication/consumer APT verification is recorded after completion below.

## PAM-authenticated approver sessions — package 0.4.0 (2026-09-27)

### Scope and security outcome

Mayi 0.4.0 adds an authenticated local entry gate to `mayi-approve` while preserving Protocol 5 and all broker-side peer-UID/group/view/one-shot checks. Before any approval-socket connection or request display, the console requires a controlling interactive TTY, verifies the actual calling UID's fixed approver-group membership (GID 23013), resolves that UID's NSS username, and authenticates the same account through the dedicated root-owned `/etc/pam.d/mayi-approve` service. The service file is required, regular, root-owned, single-link, and not group/world writable; absence or unsafe metadata fails closed rather than falling back to PAM's `other` service. The actual controlling terminal path is supplied to PAM as `PAM_TTY` so host account policy can apply terminal-specific rules. PAM includes the host's common authentication and account policies. Echo-off responses are read from `/dev/tty`; PAM-supplied terminal controls are escaped, catchable cancellation signals restore terminal state, and unsupported echo-on prompts and conversation errors fail closed. The console accepts no options and does not consume password credentials from argv, environment, or piped stdin. Password input is zeroed in the client-owned buffer, and the PAM response buffer is cleared on local conversation failure. A successful PAM handle is ended immediately; authentication state lives only in the console process, so exit/restart requires fresh authentication.

The change does not alter request authorization, broker queue/approval behavior, privilege boundaries, or restart semantics. Queue/results persistence across broker restart remains **NOT CLAIMED**. The filesystem executor remains **DISCONNECTED / INCOMPLETE**.

### Exact artifact and build provenance

- Package: `executor/target/debian/mayi_0.4.0_amd64.deb` (`mayi 0.4.0 amd64`)
- SHA-256: `d0a28d1e0e46837f395bc687b93f76742a91056a33358a5201b5a6ca28946f86`
- Dependencies: `adduser`, `init-system-helpers`, `libc6 (>= 2.28)`, `python3 (>= 3.7)`, `man-db`, `libpam0g (>= 1.1.8)`, and `libpam-runtime`.
- TPA 0.4.0 metadata: `Created-At: 2026-09-27T12:40:21Z`; provenance enabled. Builder source revision is `ab9da01d7728+dirty`.
- Built in disposable Debian 10.13 (Buster): glibc `2.28-10+deb10u3`, GCC 8.3.0, Rust/Cargo 1.95.0, PAM development library installed. Both native executables have `GLIBC_2.28` as their highest referenced GLIBC symbol.
- Mayi working tree was dirty and uncommitted at build; clean-source byte-for-byte reproducibility is **not claimed**. The qualified artifact was not rebuilt/replaced during qualification. The 0.3.2 artifact remains byte-for-byte unchanged.
- No publication, deployment, real-host access, or real-host modification occurred.

### Exact-artifact Debian/systemd qualification matrix

`executor/package/qualify-systemd.py` pinned and verified the artifact hash before each suite. Disposable containers ran systemd as PID 1 with private cgroups, no host mounts, and no runtime network. Fresh installs passed on all suites; upgrades from 0.3.2 passed on all suites. Trixie additionally tested upgrades from 0.2.0, 0.2.1, 0.2.2, 0.3.0, and 0.3.1. Bookworm fresh installation used `apt-get install` on the exact local `.deb`. Every full lifecycle environment passed 100 executor and 100 broker restarts.

| Debian | Result |
| --- | --- |
| 10 Buster | Fresh 0.4.0 install; upgrades from 0.3.1 and 0.3.2; PAM, runtime, queue, man-page, conffile, socket, and systemd lifecycle gates PASS. |
| 11 Bullseye | Same fresh/upgrade and full PAM/runtime/systemd gates PASS. |
| 12 Bookworm | Same gates PASS; fresh local-package APT install and 0.3.2 upgrade PASS. |
| 13 Trixie | Fresh install and upgrades from 0.2.0 through 0.3.2; full gates PASS. |

### PAM-specific qualification

| Gate | Result |
| --- | --- |
| Eligible user + valid PAM password on controlling PTY; echo disabled; process reaches approval console | PASS |
| Wrong password, PAM service-file removal, PAM account/PAM policy failure | PASS — no authenticated console or pending-request display |
| Broker stopped during failed-auth probe | PASS — password prompt occurs before any broker connection; auth fails without broker |
| Same account in requester and approver groups | PASS — one authentication supports multiple decisions within the same process |
| Separate requester-only and approver-only accounts | PASS — requester UID is preserved; approver UID is the actual PAM-authenticated caller |
| Primary-GID and supplementary-GID role membership | PASS |
| PAM username environment spoof and `MAYI_PASSWORD` environment variable | PASS — neither substitutes for TTY authentication of the calling NSS UID |
| `mayi-approve --password`, piped stdin, and non-interactive invocation | PASS — rejected without reading a password |
| Authentication state after process exit/restart | PASS — a new console process authenticates again |
| PAM conffile remove/reinstall, local modification preservation, purge | PASS |
| PAM password absent from terminal output and broker logs | PASS |

The legacy fake-broker PTY unit suite is skipped in ordinary host pytest because it predates the mandatory PAM gate; the package qualification uses disposable accounts and PTYs and exercises the installed console end-to-end. Repository checks: Rust **74 + 5**, including PTY cancellation/terminal-echo restoration and PAM terminal-control sanitization tests; Clippy with warnings denied; Python **51 passed, 9 skipped** (including **2** approval-launcher tests; nine legacy console PTY cases skipped); Python/shell syntax, formatting, `git diff --check`, and groff rendering.

## Man-page package release 0.3.2 (2026-09-27)

### Scope and outcome

Mayi 0.3.2 is a packaging/documentation release. It installs `mayi(1)` at `/usr/share/man/man1/mayi.1.gz` and the workflow guide at `/usr/share/man/man7/mayi-workflow.7.gz`, making `man mayi` and `man mayi-workflow` work through normal Debian lookup. The package adds `man-db` as a dependency. The Mayi runtime source, authorization, approval, queue, dependency, and filesystem behavior were not changed. No separate `mayi-approve(1)` page is provided.

The exact artifact passed fresh install and 0.3.1 upgrade qualification on Debian 10–13, including installed manual lookup/rendering and runtime/lifecycle checks. The Debian 12 fresh installation also used `apt-get install` on the local package. The 0.3.1 `.deb` remains byte-for-byte unchanged. The workflow page is now package content as well as repository documentation. Queue/results remain in-memory and the filesystem executor remains disconnected/**INCOMPLETE**.

### Artifact and build

- Package: `executor/target/debian/mayi_0.3.2_amd64.deb`
- SHA-256: `f5e81423e198cb386584de5a5060d429733b9205499ca73f5a76a512729159b1`
- TPA metadata: version 0.4.0; `Created-At` `2026-09-27T07:16:59Z`; provenance enabled.
- Build environment: disposable Debian 10.13 (Buster), `libc6 2.28-10+deb10u3`, GCC 8.3.0, Rust/Cargo 1.95.0; apt source pinned to the 2024-06-12 Buster snapshot. Native executables require at most `GLIBC_2.28`.
- TPA builder binary: Go build metadata reports module revision `ab9da01d7728+dirty`; the TPA source checkout has separate uncommitted state. This builder detail is recorded rather than implying a clean TPA build.
- The Rust/Python runtime source diff from v0.3.1 is empty. Native executables were rebuilt and their byte hashes differ from the historical 0.3.1 binaries; runtime behavior was qualified, but binary byte-identity is not claimed. The binary SHA-256 changes are `mayi-executor`: `7e565ac1c5aa8125d5e00e201fdec115233e20de5797bb0252e2a3058161cc30` → `19183a8e8cd48e8f803fe1b2584f0ac1b5ef2b2976a2d7ef8c212fefe733607f`; `privileged-executor`: `eb953e015bf8baa2fd1ad4fb96b6fef180af3f10f17c4cddbf77effc8ef2360` → `57d2d2ceb088139bdc481f8da3c48392c0c8a54717d4a525cd8f977731ba1b89`. Both builds retain the `GLIBC_2.28` maximum. The 0.3.1 `.deb` SHA-256 remains `9162530d3052389f5b84edef2680e379350bbd79a0981e247628d08a1df1b57e`.
- Artifact was built from the uncommitted 0.3.2 source snapshot before the qualification-gated release commit. Clean-source byte-for-byte reproducibility is **not claimed**. The final commit records the packaged source after qualification; no rebuild or replacement of the qualified artifact is planned.

### Package and installed-manual checks

`dpkg-deb` inspection confirms both compressed pages are present at the expected section paths. Decompressing either packaged page matches its repository source byte-for-byte. The package declares `man-db`; disposable installs passed `man -w mayi`, `man -w mayi-workflow`, `man mayi`, `man 1 mayi`, `man mayi-workflow`, and `man 7 mayi-workflow` with the normal man path (only the pager was set to `cat` for noninteractive capture). The man pages are not installed as package source or under a nonstandard manual path. TPA package metadata declares `libc6 (>= 2.28)`, `python3 (>= 3.7)`, and `man-db` in addition to the existing package dependencies.

### Debian 0.3.2 qualification matrix

All tests ran in disposable containers with systemd as PID 1, no host mounts, and no runtime network. Each suite covered fresh install, upgrade from 0.3.1, installed manual lookup, requester/approver and synchronous execution, queue/dependency/wait/failure-budget behavior, security regressions, package-setup failure, and systemd lifecycle including 100 executor and 100 broker restarts per full lifecycle run. Debian 13 additionally exercised historical upgrades. Debian 12 fresh install used apt on the local `.deb`; the other installs used dpkg.

| Debian | Result |
| --- | --- |
| 10 Buster | Fresh install and 0.3.1 upgrade; installed man pages, runtime/security, and lifecycle qualification PASS. |
| 11 Bullseye | Same 0.3.2 fresh/upgrade and installed-manual/runtime/lifecycle gates PASS. |
| 12 Bookworm | Same gates PASS; fresh install via `apt-get install` on the local artifact, then upgrade from 0.3.1 PASS. |
| 13 Trixie | Fresh install and upgrades from 0.2.0, 0.2.1, 0.2.2, 0.3.0, and 0.3.1; all installed-manual/runtime/lifecycle gates PASS. |

Repository checks also passed: Python tests 58/58, Rust tests 71 + 5, Clippy with warnings denied, Rust formatting, Python/shell syntax, `git diff --check`, and groff rendering of both manual pages. The real Debian 12.15 host was not accessed or modified for this release. Debian 10 is technically compatible but EOL; Debian 12+ remains the recommended operational baseline.

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
