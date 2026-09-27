# Mayi exact-command approval MVP package

This TPA-built Debian package installs Mayi 0.3.2: the Protocol 5 broker, synchronous and asynchronous exact-command clients, persistent approval console, and separate privileged executor. Its technical compatibility floor is Debian 10 (Buster), glibc 2.28, and Python 3.7; Debian 10 is EOL, so see the root-level `DEBIAN_COMPATIBILITY.md` before treating that as an operational OS support recommendation.

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

It groups connected dependency DAGs and prints topological command indices, exact executable/argv, requester UID, request ID, and explicit executor identity UID 0 / GID 23012. It refreshes and prints arrivals while waiting. `a` approves all pending commands in the displayed connected set; `s` skips it without changing authority; `d` denies selected/all pending commands; `f` requests follow-up; numeric indices approve a subset in display order, regardless of typed order; `q` exits. Aliases `y/n/e` remain available. Decisions use fresh one-shot broker views bound to the actual approver UID.

## Execution and security boundary

This is broad human-gated root execution, not a command allowlist or semantic safety filter. The approved executable must be canonical, root-owned, executable, non-group/world-writable, and directly under `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, or `/bin`. CLI, broker, and executor independently validate path and argv. The executor authenticates exact broker UID 23002 via `SO_PEERCRED`, clears the environment to fixed `PATH`, `LANG`, `LC_ALL`, and `HOME`, uses `/` cwd and `/dev/null` stdin, and caps output at 64 KiB per stream. Arguments are limited to 128 entries, 1,024 UTF-8 bytes each, and 2,048 total bytes. The human must assess the exact executable and every argument; explicitly requesting a shell executable remains possible.

The privileged executor durably journals each broker-derived request ID before spawn and never retries an ambiguous handoff. A queue dispatch is at-most-once, not transactional: commands may partially mutate system state before failing. The filesystem executor remains disconnected and **INCOMPLETE**; its operations are not enabled by this package.

## Roles, service accounts, and systemd

Broker UID/GID is 23002/23012; the privileged executor runs as UID 0 with primary GID 23012. Root-controlled role groups are `mayi-requester` GID 23011 and `mayi-approver` GID 23013. NSS authorization checks primary and supplementary membership on each connection; actual peer UID continues binding request ownership and approval views. The package does not add human users to role groups. Inspect IDs and configure only intended members. Legacy 0.2.0 accounts are preserved on upgrade, without special authority except configured group membership.

On systemd systems, postinst reloads units and makes the notify-ready executor available before the broker; upgrades restart the executor and then start the broker using `deb-systemd-invoke`. The broker has `Requires=`/`After=` readiness dependencies. The package does not override Debian service policy.

## Build artifact and provenance

```sh
cd ~/projekte/tpa && go build -o /tmp/tpa .
cd /home/eugen/projekte/mayi
TPA_BIN=/tmp/tpa ./executor/package/build-deb.sh
```

`build-deb.sh` links against the libc where Cargo runs; running it on a newer host can create a package that cannot run on the declared baseline. The release artifact below was built inside the Debian 10 baseline.

Artifact: `executor/target/debian/mayi_0.3.2_amd64.deb`; SHA-256 `f5e81423e198cb386584de5a5060d429733b9205499ca73f5a76a512729159b1`; TPA `Created-At` `2026-09-27T07:16:59Z`. TPA 0.4.0; provenance enabled. Depends on `adduser`, `init-system-helpers`, `libc6 (>= 2.28)`, `python3 (>= 3.7)`, and `man-db`. Built in a disposable Debian 10.13 environment with glibc 2.28-10+deb10u3 and Rust/Cargo 1.95.0. The TPA binary's Go build metadata reports source revision `ab9da01d7728+dirty`. The artifact came from the uncommitted 0.3.2 source snapshot before the qualification-gated commit; clean-source byte-for-byte reproducibility is not claimed. The 0.3.1 artifact remains unchanged.

## Man pages and qualification

The package installs `man/mayi.1` as `/usr/share/man/man1/mayi.1.gz` and `man/mayi-workflow.7` as `/usr/share/man/man7/mayi-workflow.7.gz`. The pages use Debian's normal man-page lookup; `man-db` is a package dependency so `man mayi` and `man mayi-workflow` are available after installation. The workflow guide describes the persistent approval-console controls; no separate `mayi-approve(1)` page is installed.

`python3 executor/package/qualify-systemd.py` qualifies the exact 0.3.2 artifact on disposable Debian 10–13: fresh install, upgrade from 0.3.1, installed `man` lookup/rendering, runtime and queue regressions, and systemd lifecycle gates. Debian 12 fresh installation uses `apt-get install`; Trixie additionally checks upgrades from 0.2.0 through 0.3.0. Set `MAYI_DEBIAN_SUITE` to select a suite. No real-host operation is part of this release test. The filesystem executor remains **INCOMPLETE**.

The detailed record is in `MVP_QUALIFICATION.md`. The filesystem executor remains **INCOMPLETE**.

## Socket restart and stale-entry handling

The executor serializes instances with a root-owned, no-follow lock in `/run/mayi/executor`. Before reclaiming its exact socket path it requires a Unix socket owned by root:GID 23012, mode `0660`, link count 1, and treats only `ECONNREFUSED` as proof of staleness. It rechecks device/inode and ownership before unlinking exactly that entry. The parent is root-owned mode `0750`; sibling cleanup is never performed. Graceful shutdown removes only its owned socket inode; crash recovery uses the same checks. The broker applies corresponding narrow checks to its request and approval endpoints and serializes both listeners with a lock. Live, foreign, unexpected, or ambiguous objects fail closed and are preserved.
