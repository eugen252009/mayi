# mayi

`mayi <command> [args...]` submits one exact executable-and-argv request to a Rust-owned Protocol 5 approval broker and waits for a human decision. The synchronous interface is preserved: `y` permits one execution; `n` executes nothing and exits 10; `e` executes nothing and exits 20. For asynchronous jobs, `mayi --queue [--after rq_<id>]... <command> [args...]` returns a broker-generated opaque request ID immediately. `mayi --wait [--fail=N] [--fail-instant] <id>...` observes results and `mayi --status <id>` reports one job. Queue dependencies must reference requests owned by the same authenticated requester UID; only successful dependencies permit execution. The persistent `mayi-approve` console displays exact executable/argv and dependencies, supports `a/s/d/f`, aliases `y/n/e`, and numeric selection. No shell command string, requester-supplied environment, working directory, or file descriptor is sent.

```sh
mayi systemctl reload nginx
# Or queue a dependent operation and retain its returned rq_<id>:
mayi --queue --after rq_0123456789abcdef0123456789abcdef /usr/bin/systemctl reload nginx
mayi --wait --fail=0 rq_0123456789abcdef0123456789abcdef
# In a persistent approver terminal/session:
mayi-approve
# Enter a (approve), s (skip), d (deny), f (follow-up), numeric indices, or q.
```

Requester and approver authorization uses the root-controlled `mayi-requester` and `mayi-approver` Unix groups. A user may belong to both for single-user operation; the kernel-authenticated UID still identifies each request and approval. The broker and privileged executor are separate processes. The broker authenticates requester and approver UIDs with `SO_PEERCRED`; the executor separately checks that its peer UID is the configured broker UID. `SO_PEERCRED` authenticates a UID, not a particular process, executable, or human.

## Execution scope and limits

This is a broad, human-gated command MVP, **not** a command allowlist or semantic safety filter. Approved commands run with executor identity UID 0 / primary GID 23012. The approval display makes that identity explicit. The executable must resolve to a root-owned, executable, non-group/world-writable file directly under one of `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`; path components and symlinks are checked independently by CLI, broker, and executor. Arguments are bounded (128 entries, 1,024 UTF-8 bytes each, 2,048 total bytes). The executor clears the environment, sets fixed `PATH`, `LANG`, `LC_ALL`, and `HOME`, uses `/` as cwd and `/dev/null` as stdin, and bounds captured stdout/stderr. A requester can explicitly request a shell executable and its argv; the broker does not interpret a shell string, but the approver must assess the displayed executable and every argument.

The executor journals a one-shot request ID before spawning and does not retry ambiguous handoffs. Replayed IDs are not executed; if a result cannot be proven, Mayi reports execution unknown (16). Execution is not a transaction: an approved command may have partially changed system state before it exits or loses its response.

The structured filesystem executor remains disconnected and independently **INCOMPLETE**. Existing file operations do not gain a privileged filesystem handoff. This release adds no filesystem execution or mutation; all 0.3.2 qualification used disposable containers, and the real host was not accessed or modified for this release.

## Install and package

Build the Debian package with TPA provenance enabled:

```sh
cd ~/projekte/tpa && go build -o /tmp/tpa .
cd /home/eugen/projekte/mayi
TPA_BIN=/tmp/tpa ./executor/package/build-deb.sh
```

`build-deb.sh` links native executables against the libc of the environment running Cargo. Do not treat a build on a newer host as a portable release. The 0.3.2 release artifact below is built in the Debian 10 baseline environment.

Artifact: `executor/target/debian/mayi_0.3.2_amd64.deb` (SHA-256 `f5e81423e198cb386584de5a5060d429733b9205499ca73f5a76a512729159b1`, TPA `Created-At` `2026-09-27T07:16:59Z`). TPA provenance is enabled; dependencies include `libc6 (>= 2.28)`, `python3 (>= 3.7)`, and `man-db`. The native executables require at most `GLIBC_2.28`. The package installs `mayi(1)` and `mayi-workflow(7)`; `man mayi` and `man mayi-workflow` use normal Debian man-page discovery. The 0.3.1 artifact remains unchanged. The 0.3.2 binaries were rebuilt from unchanged runtime sources; byte-identical binary reproduction is not claimed. Debian 10 is technically compatible but EOL, so Debian 12+ remains the recommended operational baseline. It provisions fixed system broker UID 23002 and role/socket groups `mayi-requester` GID 23011, `mayi-broker-socket` GID 23012, and `mayi-approver` GID 23013. Any actual user can be added to the role groups; inspect IDs before deployment. The package installs systemd units and enables the broker/executor on systemd systems. A human operator in `mayi-approver` can run `mayi-approve` directly; no sudo or UID switching is required. The package's broker/service accounts remain separate system identities.

## Qualification

`executor/package/qualify-systemd.py` qualifies the exact 0.3.2 artifact on disposable Debian 10–13 environments, including fresh install, 0.3.1 upgrade, installed `man` lookup/rendering, synchronous/queued runtime regressions, and systemd lifecycle. Debian 12 fresh install used `apt-get install` on the local `.deb`; Trixie also passed historical upgrades. The administrator previously reported deployment and smoke testing on the real Debian 12.15 host; this release work does not access or modify it.

See the CLI manual [`man/mayi.1`](man/mayi.1) and the operator guide [`man/mayi-workflow.7`](man/mayi-workflow.7). In the repository, render either with `man ./man/mayi.1` or `man ./man/mayi-workflow.7`; after package installation use `man mayi` and `man mayi-workflow`. Also see [PROTOCOL.md](PROTOCOL.md), [SECURITY_BOUNDARY.md](SECURITY_BOUNDARY.md), [executor/package/README.md](executor/package/README.md), [MVP_QUALIFICATION.md](MVP_QUALIFICATION.md), and [FILESYSTEM_EXECUTOR_REMEDIATION.md](FILESYSTEM_EXECUTOR_REMEDIATION.md) for implementation details, evidence, and remaining limits. The earlier qualification in [PRIVILEGED_BOUNDARY_QUALIFICATION.md](PRIVILEGED_BOUNDARY_QUALIFICATION.md) is historical and does not qualify this MVP.
