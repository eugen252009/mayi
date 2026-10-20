> Archive view: maintainer-local paths have been omitted. Commands containing
> `[local-only path omitted]` are historical records, not runnable instructions.
> Original bytes remain at the commit/path recorded by the documentation checker.

# Mayi exact-command approval MVP package

Mayi 0.4.1 remains the published stable baseline. Current supported Debian runtime targets are Debian 11–13 amd64; Debian 10 is not supported, although it remains an acceptable build environment for a portable GLIBC baseline. Candidate 0.4.1-5 requires broker-verified NSS approver-group membership and broker-side PAM authentication for every decision. Its exact artifact passed direct-systemd qualification on Debian 11–13 and is **READY FOR INDEPENDENT SECURITY REVIEW**, not production-ready or published. Keep earlier artifacts unchanged. See [`../../DEBIAN_COMPATIBILITY.md`](../../DEBIAN_COMPATIBILITY.md) for capability requirements and evidence. The package maintainer is Eugen Lupricht <mayi@lupricht.net>. Security reports: mayi-security@lupricht.net.

This TPA-built Debian package targets Mayi 0.4.1: the Protocol 5 broker, synchronous and asynchronous exact-command clients, per-decision broker-side PAM authentication service, interactive approval console, and separate privileged executor. Its supported runtime targets are Debian 11 (Bullseye), Debian 12 (Bookworm), and Debian 13 (Trixie), amd64. The portable native-binary GLIBC floor (2.28) and package Python floor (3.7) are not OS-support claims; Debian 10 is not a supported runtime. See the root-level `DEBIAN_COMPATIBILITY.md` for capability requirements and qualification evidence.

## Request and approval flows

Synchronous execution remains supported:

```sh
mayi /usr/bin/systemctl reload nginx
```

The requester waits for approval; the approver chooses `y` (approve once), `n` (deny), or `e` (follow-up). Deny executes nothing (exit 10), follow-up executes nothing (exit 20), and a nonzero child exit is exit 14.

Queued execution is asynchronous at submission:

```sh
id=$(mayi --queue /usr/bin/true)
next=$(mayi --queue --after "$id" /usr/bin/id)
mayi --wait --fail=0 "$id" "$next"
mayi --status "$next"
```

The queue command prints exactly one broker-generated opaque `rq_<32 lowercase hex>` ID on success and no ID on error. The immutable object is the canonical executable and exact argv; no shell, requester environment, cwd, redirection, or descriptors are transported. Every queued operation still requires explicit human approval. `--after` may be repeated; each dependency must identify a retained queued request belonging to the same authenticated requester UID. A command is dispatched once only after approval and successful completion of every dependency. A terminal unsuccessful dependency blocks descendants. The broker detects dependency cycles and rejects duplicate, unknown, non-queued, or cross-requester dependencies. The queue is bounded (128 retained requests globally, eight active requests per requester) and queued approvals expire after 24 hours.

`mayi --wait [--fail=N] [--fail-instant] <id>...` observes jobs without executing or cancelling them. The default failure budget is zero. Terminal states other than `SUCCEEDED` consume the budget; `--fail-instant` exits once the budget is exceeded, without cancelling other jobs. Output includes each observed request ID, state, Mayi result, child status when available, and blocking dependency. `mayi --status <id>` reports one job. Result state is held in broker memory, not persisted: broker restart invalidates queued state and results, and neither request nor execution is replayed. Keep IDs and observe results before broker restart; this release does not claim restart-safe queue retention.

Run one persistent approval console in an interactive approver terminal:

```sh
mayi-approve
```

The console verifies the actual calling UID's NSS-backed approver-group membership and requires an interactive controlling terminal. It accepts no options and does not read credentials from argv, environment variables, or piped stdin. Listing and viewing requests do not authenticate a decision. For every approve/deny/follow-up decision, the console passes exactly one controlling-terminal descriptor to the broker using `SCM_RIGHTS`. The broker verifies the kernel peer UID's NSS approver-group membership, sends a correlated request and that terminal descriptor to the separate PAM helper, and rechecks group membership after successful authentication immediately before the state transition. The helper runs PAM service `mayi-approve` for the broker-derived peer UID, checks account policy, supports echo-off and echo-on prompts, sanitizes terminal output, and restores terminal state on catchable termination and timeout. No password, reusable PAM token, or successful session assertion travels through the protocol; every decision authenticates anew. PAM failure, locked/ineligible accounts, malformed helper responses, and terminal errors fail closed. The package installs `/etc/pam.d/mayi-approve` as a conffile including the host's `common-auth` and `common-account` policies.

After startup, it groups connected dependency DAGs and prints topological command indices, exact executable/argv, requester UID, request ID, and explicit executor identity UID 0 / GID 23012. Arguments use separate shell-quoted display values, with the actual argv[0] shown next to the executable; this is display notation, not shell input. After an accepted allow/deny/follow-up decision, the console clears only the visible screen when stdout is a TTY and `TERM` is usable, preserving scrollback; broker rejection/errors do not clear the request display. It refreshes and prints arrivals while waiting. `a` approves all pending commands in the displayed connected set; `s` skips it without changing authority; `d` denies selected/all pending commands; `f` requests follow-up; numeric digits approve a subset in display order, regardless of typed order. Numeric selection accepts one digit per index and currently addresses indices 0–9 only; use `a` when a set includes higher indices. `q` exits. Aliases `y/n/e` remain available. Decisions use fresh one-shot broker views bound to the actual approver UID.

## Execution and security boundary

This is broad human-gated root execution, not a command allowlist or semantic safety filter. The approved executable must be canonical, root-owned, executable, non-group/world-writable, and directly under `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, or `/bin`. CLI, broker, and executor independently validate path and argv. The executor authenticates exact broker UID 23002 via `SO_PEERCRED`, clears the environment to fixed `PATH`, `LANG`, `LC_ALL`, and `HOME`, uses `/` cwd and `/dev/null` stdin, and caps output at 64 KiB per stream. Arguments are limited to 128 entries, 1,024 UTF-8 bytes each, and 2,048 total bytes. The human must assess the exact executable and every argument; explicitly requesting a shell executable remains possible.

The privileged executor durably journals each broker-derived request ID before spawn and never retries an ambiguous handoff. A queue dispatch is at-most-once, not transactional: commands may partially mutate system state before failing. The filesystem executor remains disconnected and **INCOMPLETE**; its operations are not enabled by this package.

## Roles, service accounts, and systemd

Broker UID/GID is 23002/23012; candidate 0.4.1-4's PAM authority runs as UID 0/GID 23012, bounded to `CAP_DAC_READ_SEARCH` with `NoNewPrivileges` and systemd filesystem sandboxing; the privileged executor also runs as UID 0/GID 23012. Root-controlled role groups are `mayi-requester` GID 23011 and `mayi-approver` GID 23013. NSS authorization checks primary and supplementary membership on each broker connection and again after PAM before a decision. The helper accepts only broker UID 23002 from the fixed `/system.slice/mayi-broker.service` cgroup and authenticates the exact broker-derived peer UID for each decision. Its root PAM authority is a privileged trust component; it has no command execution path and is not an unprivileged helper. Non-systemd or customized cgroup placement fails closed. Actual peer UID continues binding request ownership and approval views. The package does not add human users to role groups. Inspect IDs and configure only intended members. Legacy 0.2.0 accounts are preserved on upgrade, without special authority except configured group membership.

On systemd systems, postinst reloads units and starts the notify-ready executor and PAM helper before the broker. Upgrades restart the executor, PAM helper, and broker in order using `deb-systemd-invoke`, so no pre-upgrade broker remains active with group-only approval semantics. The broker has `Requires=`/`After=` dependencies on the executor and PAM helper. The package does not override Debian service policy.

## Build artifact and provenance

The release build uses the TPA CLI and `executor/package/build-deb.sh`. From a TPA source checkout, build the CLI, then run the Mayi script from the Mayi repository root:

```sh
# In a TPA source checkout:
go build -o /tmp/tpa .

# In the Mayi source checkout root:
TPA_BIN=/tmp/tpa ./executor/package/build-deb.sh
```

`build-deb.sh` links against the libc where Cargo runs and requires `libpam0g-dev`; running it on a newer host can create a package that cannot run on the declared baseline. The release artifact below was built inside the Debian 10 baseline.

Historical 0.4.1 artifact: `executor/target/debian/mayi_0.4.1_amd64.deb`, SHA-256 `22409abd977d4d14113ee34e47ed78f94a4e975da84e9606f5fe704116f59ab0`; package identity `mayi 0.4.1 amd64`. This immutable artifact retains its original metadata and is not rebuilt. Package revision `0.4.1-1` is built as `executor/target/debian/mayi_0.4.1-1_amd64.deb`; its exact qualification and publication evidence will be recorded separately. The Debian package includes `/usr/share/doc/mayi/copyright` under MIT. TPA metadata records `Created-At: 2026-09-27T14:06:03Z`; provenance is enabled. It retains the 0.4.0 runtime dependencies, including `libpam0g (>= 1.1.8)` and `libpam-runtime`, and the PAM conffile. The artifact was built from clean source revision `7e7636838507b0399d914741935e9673ed09e710` on disposable Debian 10.13 (glibc 2.28-10+deb10u3, GCC 8.3.0, Rust/Cargo 1.95.0); both native executables require at most `GLIBC_2.28`. It was not rebuilt after qualification. The immutable 0.4.0 artifact remains `executor/target/debian/mayi_0.4.0_amd64.deb`, SHA-256 `d0a28d1e0e46837f395bc687b93f76742a91056a33358a5201b5a6ca28946f86`; the historical 0.3.2 artifact remains unchanged: `executor/target/debian/mayi_0.3.2_amd64.deb`, SHA-256 `f5e81423e198cb386584de5a5060d429733b9205499ca73f5a76a512729159b1`. The 0.4.0 build provenance was `ab9da01d7728+dirty`; that historical package is not claimed reproducible from a clean revision.

## Candidate 0.4.1-5 exact-artifact qualification

- Exact artifact: `[local-only path omitted]`, `mayi 0.4.1-5 amd64`, SHA-256 `cebe101be7cf9f1501ea74949f76ead00bc7e6d593c216ba0a9a6478fa05f381`.
- Passed direct-systemd exact-artifact tests on Debian 11 Bullseye (kernel 5.10/systemd 247), Debian 12 Bookworm (6.1/252), and Debian 13 Trixie (6.12/257). The matrix and capability evidence are in [`../../DEBIAN_COMPATIBILITY.md`](../../DEBIAN_COMPATIBILITY.md) and `[local-only path omitted]`.
- **READY FOR INDEPENDENT SECURITY REVIEW**; not production-ready, published, or authorized for staging.

## Historical candidate 0.4.1-4 artifact and qualification status (not current support policy)

- Exact artifact: `executor/target/debian/mayi_0.4.1-4_amd64.deb` (`mayi 0.4.1-4 amd64`), SHA-256 `0289b3c0bb5f43680a97574ca46f062004992ba71abc74d3d94ce2b6a5e42287`.
- Built in disposable Debian 10/Buster with glibc 2.28, GCC 8.3.0, Rust/Cargo 1.95.0, and TPA 0.6.1. Extracted payload matched the final staging tree; binaries require at most `GLIBC_2.28`.
- The exact-artifact fresh/upgrade, PAM/adversarial, setup-failure, and systemd lifecycle matrix passed on Debian 10–13, including upgrades from 0.4.1-3. Cases include raw approval without a TTY descriptor, forged identity fields, same-UID helper access outside the broker cgroup, failed/locked credentials, helper outage, NSS role revocation during PAM, replay, view transfer, concurrency, and broker restart invalidation.
- The PAM authority runs as root with only `CAP_DAC_READ_SEARCH`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, and narrow writable runtime paths. It accepts only broker UID 23002 from `/system.slice/mayi-broker.service`. This fixed systemd cgroup dependency fails closed when customized or when systemd is absent. Only the stock local Debian PAM stack was end-to-end qualified; third-party MFA/SSSD/custom modules were not, and modules needing writes outside the socket and `/run/faillock` may fail closed. The authority is privileged and must remain in the independent review scope.
- **The package matrix passing is not independent review or final release qualification.** Candidate 0.4.1-4 is not production-ready, published, or to be staged before independent review. See [`../../AUDIT_REPORT_0.4.1-4.md`](../../AUDIT_REPORT_0.4.1-4.md) and [`../../MVP_QUALIFICATION.md`](../../MVP_QUALIFICATION.md).

## Man pages and qualification

The package installs `man/mayi.1` as `/usr/share/man/man1/mayi.1.gz` and `man/mayi-workflow.7` as `/usr/share/man/man7/mayi-workflow.7.gz`. The pages use Debian's normal man-page lookup; `man-db` is a package dependency so `man mayi` and `man mayi-workflow` are available after installation. The workflow guide describes the persistent approval-console controls; no separate `mayi-approve(1)` page is installed.

`python3 executor/package/qualify-systemd.py` qualified the exact 0.4.1-1 artifact on disposable Debian 10–13 containers, using fresh installs and upgrades from both 0.4.0 and 0.4.1. It covers PAM success/failure through a disposable TTY, denial before broker access, same-account and separate requester/approver accounts, rejected non-interactive/argv/environment paths, process-local authentication, console refresh/argv rendering, package version/maintainer/license metadata, PAM conffile remove/reinstall/preserve/purge, installed man pages, runtime/queue regressions, and systemd lifecycle. The historical 0.4.1 artifact qualification is recorded separately. No production host was accessed or modified, and no deployment or Synology work occurred. TPA.run publication and consumer APT verification are recorded in the release qualification record. The filesystem executor remains **INCOMPLETE**.

The detailed release, qualification, publication, and APT-consumer record is in [`../../MVP_QUALIFICATION.md`](../../MVP_QUALIFICATION.md). The current filesystem-executor gate is summarized in [`../../docs/FILESYSTEM_EXECUTOR_STATUS.md`](../../docs/FILESYSTEM_EXECUTOR_STATUS.md); filesystem execution remains **DISCONNECTED / INCOMPLETE**.

## Socket restart and stale-entry handling

The executor serializes instances with a root-owned, no-follow lock in `/run/mayi/executor`. Before reclaiming its exact socket path it requires a Unix socket owned by root:GID 23012, mode `0660`, link count 1, and treats only `ECONNREFUSED` as proof of staleness. It rechecks device/inode and ownership before unlinking exactly that entry. The parent is root-owned mode `0750`; sibling cleanup is never performed. Graceful shutdown removes only its owned socket inode; crash recovery uses the same checks. The broker applies corresponding narrow checks to its request and approval endpoints and serializes both listeners with a lock. Live, foreign, unexpected, or ambiguous objects fail closed and are preserved.
