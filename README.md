# mayi

`mayi <command> [args...]` submits one exact executable-and-argv request to a Rust-owned Protocol 5 approval broker and waits for a human decision. The synchronous interface is preserved: `y` permits one execution; `n` executes nothing and exits 10; `e` executes nothing and exits 20. For asynchronous jobs, `mayi --queue [--after rq_<id>]... <command> [args...]` returns a broker-generated opaque request ID immediately. `mayi --wait [--fail=N] [--fail-instant] <id>...` observes results and `mayi --status <id>` reports one job. Queue dependencies must reference requests owned by the same authenticated requester UID; only successful dependencies permit execution. The persistent `mayi-approve` console displays exact executable/argv and dependencies, supports `a/s/d/f`, aliases `y/n/e`, and numeric selection. No shell command string, requester-supplied environment, working directory, or file descriptor is sent.

```sh
mayi systemctl reload nginx
# Or queue a dependent operation and retain its returned rq_<id>:
mayi --queue --after rq_0123456789abcdef0123456789abcdef /usr/bin/systemctl reload nginx
mayi --wait --fail=0 rq_0123456789abcdef0123456789abcdef
# In the human approver's own interactive terminal:
mayi-approve
# Authenticate the same Unix account with PAM, then enter a (approve), s (skip), d (deny), f (follow-up), numeric indices, or q.
```

Requester and approver authorization uses the root-controlled `mayi-requester` and `mayi-approver` Unix groups. Before opening the approval socket or displaying requests, `mayi-approve` checks the actual calling UID's approver-group membership and authenticates that same NSS account through PAM. This requires a controlling interactive terminal; passwords are entered with echo disabled and are not accepted through argv, environment variables, or piped stdin. Authentication lasts only for the lifetime of that console process; a new process requires a new authentication. A user may belong to both groups for single-account operation, or requester and approver may be separate accounts. The broker independently authenticates requester and approver peer UIDs with `SO_PEERCRED` and repeats its role checks; the executor separately checks that its peer UID is the configured broker UID. `SO_PEERCRED` authenticates a UID, not a particular process or executable. Agents may submit requests but must leave human PAM authentication and approval to the approver.

## Execution scope and limits

This is a broad, human-gated command MVP, **not** a command allowlist or semantic safety filter. Approved commands run with executor identity UID 0 / primary GID 23012. The approval display makes that identity explicit. The executable must resolve to a root-owned, executable, non-group/world-writable file directly under one of `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`; path components and symlinks are checked independently by CLI, broker, and executor. Arguments are bounded (128 entries, 1,024 UTF-8 bytes each, 2,048 total bytes). The executor clears the environment, sets fixed `PATH`, `LANG`, `LC_ALL`, and `HOME`, uses `/` as cwd and `/dev/null` as stdin, and bounds captured stdout/stderr. A requester can explicitly request a shell executable and its argv; the broker does not interpret a shell string, but the approver must assess the displayed executable and every argument.

The executor journals a one-shot request ID before spawning and does not retry ambiguous handoffs. Replayed IDs are not executed; if a result cannot be proven, Mayi reports execution unknown (16). Execution is not a transaction: an approved command may have partially changed system state before it exits or loses its response.

The structured filesystem executor remains disconnected and independently **INCOMPLETE**. Existing file operations do not gain a privileged filesystem handoff. This release adds no filesystem execution or mutation; 0.4.1 qualification uses disposable containers only, and must not access or modify the real host.

## Install and package

Build the Debian package with TPA provenance enabled:

```sh
cd ~/projekte/tpa && go build -o /tmp/tpa .
cd /home/eugen/projekte/mayi
TPA_BIN=/tmp/tpa ./executor/package/build-deb.sh
```

`build-deb.sh` links native executables against the libc of the environment running Cargo and requires the PAM development linker library (`libpam0g-dev`) there. Do not treat a build on a newer host as a portable release. Mayi 0.4.1 is a console UX-only update: after a successful allow/deny/follow-up decision the console clears only the visible screen (never scrollback), and only on a TTY with a usable `TERM`; failed decisions leave the current display intact. Commands are rendered as readable, unambiguous argv boundaries. Successful authentication no longer prints an `Authenticated.` banner or interactive auth-success event. PAM, authorization, queue, package dependencies, and executor behavior are unchanged. The exact qualified 0.4.1 artifact is `executor/target/debian/mayi_0.4.1_amd64.deb`, SHA-256 `22409abd977d4d14113ee34e47ed78f94a4e975da84e9606f5fe704116f59ab0`. The immutable 0.4.0 artifact remains `executor/target/debian/mayi_0.4.0_amd64.deb`, SHA-256 `d0a28d1e0e46837f395bc687b93f76742a91056a33358a5201b5a6ca28946f86`; 0.3.2 remains unchanged. Package 0.4.1 retains the Debian 10 glibc 2.28 / Python 3.7 floor and the 0.4.0 PAM runtime dependencies `libpam0g (>= 1.1.8)` and `libpam-runtime`, with `/etc/pam.d/mayi-approve` as a conffile. It provisions fixed system broker UID 23002 and role/socket groups `mayi-requester` GID 23011, `mayi-broker-socket` GID 23012, and `mayi-approver` GID 23013. The package does not automatically add human users to role groups. Debian 10 is technically compatible but EOL, so Debian 12+ remains the recommended operational baseline. A human member of `mayi-approver` can run `mayi-approve` directly; no sudo or UID switching is required.

## Qualification

`executor/package/qualify-systemd.py` is the Debian 10–13 disposable systemd qualification harness. The exact 0.4.1 artifact passed fresh-install and 0.4.0-upgrade qualification on Debian 10–13, including same-account and separate-account approvers, PAM success/failure, TTY/password-channel restrictions, console refresh/argv rendering, PAM conffile lifecycle, installed man pages, runtime/queue regressions, and systemd lifecycle. The qualified package is published to TPA.run `bootstrap` (`https://tpa.run/r/tparun/bootstrap`); isolated APT metadata advertises 0.4.1 and the exact-version download hash matches the qualified artifact. Publication was not deployment: no production host was accessed or modified. No Synology work began. Debian 10 is technically compatible but EOL; Debian 12+ remains the recommended operational baseline.

See the CLI manual [`man/mayi.1`](man/mayi.1) and the operator guide [`man/mayi-workflow.7`](man/mayi-workflow.7). In the repository, render either with `man ./man/mayi.1` or `man ./man/mayi-workflow.7`; after package installation use `man mayi` and `man mayi-workflow`. Also see [PROTOCOL.md](PROTOCOL.md), [SECURITY_BOUNDARY.md](SECURITY_BOUNDARY.md), [executor/package/README.md](executor/package/README.md), [MVP_QUALIFICATION.md](MVP_QUALIFICATION.md), and [FILESYSTEM_EXECUTOR_REMEDIATION.md](FILESYSTEM_EXECUTOR_REMEDIATION.md) for implementation details, evidence, and remaining limits. The earlier qualification in [PRIVILEGED_BOUNDARY_QUALIFICATION.md](PRIVILEGED_BOUNDARY_QUALIFICATION.md) is historical and does not qualify this MVP.
