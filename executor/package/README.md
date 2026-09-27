# Mayi exact-command approval MVP package

This TPA-built Debian package targets Mayi 0.4.1: the Protocol 5 broker, synchronous and asynchronous exact-command clients, PAM-authenticated persistent approval console, and separate privileged executor. Its technical compatibility floor is Debian 10 (Buster), glibc 2.28, and Python 3.7; Debian 10 is EOL, so see the root-level `DEBIAN_COMPATIBILITY.md` before treating that as an operational OS support recommendation.

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

Before opening the broker connection or displaying any request, it verifies the actual calling UID's NSS-backed approver-group membership and authenticates that same account with PAM service `mayi-approve`, passing the controlling terminal path as `PAM_TTY`. It requires an interactive controlling terminal; password prompts are read from `/dev/tty` with echo disabled. PAM-supplied terminal control characters are escaped; catchable termination signals restore terminal settings before authentication fails. It accepts no options and does not read credentials from argv, environment variables, or piped stdin. PAM/account failure fails closed. Authentication exists only in the running console process; exit or restart requires fresh authentication. The package installs `/etc/pam.d/mayi-approve` as a conffile including the host's `common-auth` and `common-account` policies. The broker independently retains all peer-UID, approver-group, and one-shot view authorization checks.

After quiet successful authentication (no `Authenticated.` banner or interactive auth-success event), it groups connected dependency DAGs and prints topological command indices, exact executable/argv, requester UID, request ID, and explicit executor identity UID 0 / GID 23012. Arguments use separate shell-quoted display values, with the actual argv[0] shown next to the executable; this is display notation, not shell input. After an accepted allow/deny/follow-up decision, the console clears only the visible screen when stdout is a TTY and `TERM` is usable, preserving scrollback; broker rejection/errors do not clear the request display. It refreshes and prints arrivals while waiting. `a` approves all pending commands in the displayed connected set; `s` skips it without changing authority; `d` denies selected/all pending commands; `f` requests follow-up; numeric indices approve a subset in display order, regardless of typed order; `q` exits. Aliases `y/n/e` remain available. Decisions use fresh one-shot broker views bound to the actual approver UID.

## Execution and security boundary

This is broad human-gated root execution, not a command allowlist or semantic safety filter. The approved executable must be canonical, root-owned, executable, non-group/world-writable, and directly under `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, or `/bin`. CLI, broker, and executor independently validate path and argv. The executor authenticates exact broker UID 23002 via `SO_PEERCRED`, clears the environment to fixed `PATH`, `LANG`, `LC_ALL`, and `HOME`, uses `/` cwd and `/dev/null` stdin, and caps output at 64 KiB per stream. Arguments are limited to 128 entries, 1,024 UTF-8 bytes each, and 2,048 total bytes. The human must assess the exact executable and every argument; explicitly requesting a shell executable remains possible.

The privileged executor durably journals each broker-derived request ID before spawn and never retries an ambiguous handoff. A queue dispatch is at-most-once, not transactional: commands may partially mutate system state before failing. The filesystem executor remains disconnected and **INCOMPLETE**; its operations are not enabled by this package.

## Roles, service accounts, and systemd

Broker UID/GID is 23002/23012; the privileged executor runs as UID 0 with primary GID 23012. Root-controlled role groups are `mayi-requester` GID 23011 and `mayi-approver` GID 23013. NSS authorization checks primary and supplementary membership on each broker connection; PAM authenticates the current approver account locally before connection. Actual peer UID continues binding request ownership and approval views. The package does not add human users to role groups. Inspect IDs and configure only intended members. Legacy 0.2.0 accounts are preserved on upgrade, without special authority except configured group membership.

On systemd systems, postinst reloads units and makes the notify-ready executor available before the broker; upgrades restart the executor and then start the broker using `deb-systemd-invoke`. The broker has `Requires=`/`After=` readiness dependencies. The package does not override Debian service policy.

## Build artifact and provenance

```sh
cd ~/projekte/tpa && go build -o /tmp/tpa .
cd /home/eugen/projekte/mayi
TPA_BIN=/tmp/tpa ./executor/package/build-deb.sh
```

`build-deb.sh` links against the libc where Cargo runs and requires `libpam0g-dev`; running it on a newer host can create a package that cannot run on the declared baseline. The release artifact below was built inside the Debian 10 baseline.

The 0.4.1 package identity is `mayi 0.4.1 amd64`; record its qualified SHA-256 here after the release gates pass. The immutable 0.4.0 artifact is `executor/target/debian/mayi_0.4.0_amd64.deb`, SHA-256 `d0a28d1e0e46837f395bc687b93f76742a91056a33358a5201b5a6ca28946f86`. TPA 0.4.0 metadata records `Created-At: 2026-09-27T12:40:21Z`; provenance is enabled. Runtime dependencies include `libpam0g (>= 1.1.8)` and `libpam-runtime`; `/etc/pam.d/mayi-approve` is a conffile. The artifact was built on disposable Debian 10.13 (glibc 2.28-10+deb10u3, GCC 8.3.0, Rust/Cargo 1.95.0); both native executables require at most `GLIBC_2.28`. The TPA builder metadata identifies source revision `ab9da01d7728+dirty`; Mayi source was a dirty, uncommitted snapshot, so clean-source byte-for-byte reproducibility is not claimed. No rebuild occurred after qualification. Historical 0.3.2 artifact remains unchanged: `executor/target/debian/mayi_0.3.2_amd64.deb`, SHA-256 `f5e81423e198cb386584de5a5060d429733b9205499ca73f5a76a512729159b1`.

## Man pages and qualification

The package installs `man/mayi.1` as `/usr/share/man/man1/mayi.1.gz` and `man/mayi-workflow.7` as `/usr/share/man/man7/mayi-workflow.7.gz`. The pages use Debian's normal man-page lookup; `man-db` is a package dependency so `man mayi` and `man mayi-workflow` are available after installation. The workflow guide describes the persistent approval-console controls; no separate `mayi-approve(1)` page is installed.

`python3 executor/package/qualify-systemd.py` qualifies the exact 0.4.1 artifact on disposable Debian 10–13 containers, using fresh installs and upgrades from 0.4.0. It covers PAM success/failure through a disposable TTY, denial before broker access, same-account and separate requester/approver accounts, rejected non-interactive/argv/environment paths, process-local authentication, console refresh/argv rendering, PAM conffile remove/reinstall/preserve/purge, installed man pages, runtime/queue regressions, and systemd lifecycle. No real-host access, deployment, publication, or modification occurred. The filesystem executor remains **INCOMPLETE**.

The detailed record is in `MVP_QUALIFICATION.md`. The filesystem executor remains **INCOMPLETE**.

## Socket restart and stale-entry handling

The executor serializes instances with a root-owned, no-follow lock in `/run/mayi/executor`. Before reclaiming its exact socket path it requires a Unix socket owned by root:GID 23012, mode `0660`, link count 1, and treats only `ECONNREFUSED` as proof of staleness. It rechecks device/inode and ownership before unlinking exactly that entry. The parent is root-owned mode `0750`; sibling cleanup is never performed. Graceful shutdown removes only its owned socket inode; crash recovery uses the same checks. The broker applies corresponding narrow checks to its request and approval endpoints and serializes both listeners with a lock. Live, foreign, unexpected, or ambiguous objects fail closed and are preserved.
