# Mayi

> **Request history correction:** `0.4.1-10~status3` shows only authoritative rq_/ch_ requests by default; `mayi history --events` exposes the broader audit trail. History JSON is now schema2 (live status/native schema1 unchanged). See HISTORY_CLASSIFICATION.md, HISTORY_EVENTS_MODE.md, HISTORY_JSON_COMPATIBILITY.md and FINAL_DECISION.md. No automatic installation/publication.

> **CLI metadata development:** `0.4.1-10~status2` adds local `--version`/`-V` and help to both entrypoints. Executable arguments remain unchanged and approval-gated; use `--` for names colliding with internal commands/options. See CLI_DISPATCH_DESIGN.md, CLI_COMPATIBILITY.md and FINAL_DECISION.md. No automatic installation or release publication.

> **Live status development:** `0.4.1-10~status1` adds `mayi-approve status [--json] [--watch] [--interval SECONDS]`. See STATUS_DESIGN.md, QUEUE_STATE_MAPPING.md and FINAL_DECISION.md. This queries live broker state; `mayi history` remains historical. No automatic installation or release publication.

> **Native audit development:** this isolated worktree adds native Journald fields and read-only `mayi history` in 0.4.1-10~journald6. See HISTORY_DESIGN.md and HISTORY_SCHEMA.md for usage, access limits and JSON. See JOURNALD_SCHEMA.md, REQUEST_CORRELATION.md and FINAL_DECISION.md for tested scope and limits. It does not replace or publish qualified 0.4.1-9.

> **Development 0.4.1-9~ui3:** explicit, broker-enforced five-minute sliding console authentication sessions are now implemented. Successful decisions renew the window; reads do not. This supersedes per-decision password claims below for the new console only. Legacy clients still use per-decision PAM. See [AUTHENTICATION_SESSIONS.md](AUTHENTICATION_SESSIONS.md) for protocol, threat-model changes and test limits. Not packaged, deployed or production-qualified.

**May I?** lets an agent or automation request a privileged local operation without giving the requester direct root credentials. The requester submits an executable and its arguments. A human opens the approval console and authenticates separately through PAM. Only a request the human explicitly approves can reach the privileged executor.

```text
agent / requester
        ↓ exact executable + argv
broker-owned immutable request
        ↓ one-shot view
human approval console
        ↓ PAM authentication of the human's Unix account
one-shot decision
        ↓ independent broker authorization
privileged executor
        ↓ direct execution of exact executable + argv
```

## Status

**STABLE / MAINTENANCE — Mayi 0.4.1 is the current stable feature baseline.** The qualified Debian package revision 0.4.1-1 corrects maintainer/license metadata and carries the current documentation; it does not claim a runtime feature change. It is published through TPA.run and verified by an isolated APT consumer. Mayi is maintained, not abandoned.

Candidate 0.4.1-5 moves PAM verification into a separate broker-verifiable authority and requires authentication for every decision. The exact artifact passed direct-systemd qualification on the supported Debian 11–13 targets and is **READY FOR INDEPENDENT SECURITY REVIEW**; this is not production readiness or publication authorization. See [`DEBIAN_COMPATIBILITY.md`](DEBIAN_COMPATIBILITY.md) for the capability requirements and exact-artifact evidence. The prior 0.4.1-4 Debian 10–13 result is historical and does not establish current Debian 10 support.

**Security limitation in published 0.4.1:** PAM is enforced by the supplied console, not by the broker protocol. A direct approval-socket client can bypass console-local PAM while satisfying broker group/view checks. Do not treat the published package as requiring PAM for every protocol approval; see [`SECURITY_BOUNDARY.md`](SECURITY_BOUNDARY.md).

- Feature development is frozen unless driven by a concrete requirement.
- Bug fixes, security fixes, and documentation fixes remain allowed.
- New platforms are on demand; breaking changes require explicit justification.
- Synology DSM is **not supported** and is deferred pending platform/vendor answers.

## Why Mayi exists

An agent can prepare and submit a request without holding root credentials. A human separately reviews and authorizes the exact operation. A typical setup gives a dedicated agent account the `mayi-requester` role and a human account the `mayi-approver` role. The roles can belong to the same Unix account, but the approval console still requires that account's PAM authentication. Separate accounts provide clearer role separation.

**Shell possession is not approval authority.** Requester identity and role membership do not authenticate a human or authorize a decision. Conversely, PAM authentication does not replace the broker's independent identity and role checks.

## Security model

- `mayi` submits an executable and structured argv; it does not send a shell command string, requester environment, working directory, or file descriptors. The command token resolves to a canonical executable in Mayi's fixed trusted system directories. The supplied argv, including argv[0], remains part of the request.
- The Rust broker authenticates local peer UIDs with `SO_PEERCRED`, checks requester/approver group membership through NSS, and owns the immutable request and approval state. Requester identity is bound to the request; the broker independently checks the approver's peer identity and authorization.
- In candidate **0.4.1-5**, `mayi-approve` checks group membership and requires an interactive controlling terminal. Each decision passes one terminal descriptor to the broker; the unprivileged broker invokes a separate, narrowly sandboxed root PAM authority for the exact peer UID and rechecks group membership before changing state. The helper is restricted to the broker UID in the fixed systemd service cgroup. No password or reusable PAM assertion is sent through broker JSON. The exact artifact passed the Debian 11–13 direct-systemd matrix and is ready for independent review; published 0.4.1 lacks this broker-side gate.
- An approval is one-shot and applies to broker-owned request state. The renderer displays that state; **renderer output is not execution input**. The executor receives the broker's stored operation, not text copied from the terminal.
- The separate privileged executor accepts requests only from the configured broker UID, revalidates the operation, and executes the exact executable + argv without shell mediation. Direct executor access is not an authorization path.
- Mayi runs an approved command as UID 0 / primary GID 23012. It is a broad human-gated command MVP—not a semantic safety analyzer or command allowlist. The approver must assess the executable and every argument. An explicitly requested shell executable can interpret its own arguments.

The display shows the resolved executable and argv[0] separately. For example, invoking `mayi systemctl restart nginx` resolves the executable path but retains `systemctl` as argv[0]. The approval display is human-readable notation, not a shell command to copy or execute.

## Installation

The Debian package revision 0.4.1-1 is available from the public TPA.run `bootstrap` APT repository. Verify that APT advertises this revision from the bootstrap repository before using it. Package availability is separate from local role configuration: installing Mayi does **not** add users to either role group.

On a supported Debian 11–13 amd64 system with the signed TPA.run `bootstrap` APT source already configured, refresh package metadata, confirm the exact 0.4.1-1 candidate, and install that package revision. Debian 10 is not a supported runtime target; its historical installation/binary compatibility did not establish the required kernel/systemd security properties.

```sh
sudo apt update
apt-cache policy mayi
sudo apt install mayi=0.4.1-1
```

The repository is `https://tpa.run/r/tparun/bootstrap`; its signed [`InRelease`](https://tpa.run/r/tparun/bootstrap/dists/stable/InRelease) metadata is consumer-visible. If the TPA.run archive keyring/source is not configured, use TPA.run's current official bootstrap procedure first. Do not add an unsigned source or bypass APT signature verification. Stop if APT does not offer the expected Mayi 0.4.1-1 package from the intended repository. The package-install command above is initial bootstrap, before Mayi is available. Installing packages and configuring local accounts require system-administrator authority. After Mayi is installed, use Mayi's approval workflow for privileged operations when it is available; do not use a second escalation path to work around a rejected request. Package publication does not install or deploy Mayi on any host.

## Initial setup

The package creates the fixed role groups `mayi-requester` and `mayi-approver`; it deliberately does not choose which human or automation account belongs to them. Have the system administrator grant only the intended memberships using the host's approved account-management procedure:

```sh
adduser AGENT_LOGIN mayi-requester
adduser HUMAN_LOGIN mayi-approver
```

Run account-management commands as an authorized system administrator. For one account in both roles, add that login to both groups.

For a single-account setup, that account may belong to both groups. Group membership alone does not authorize protocol decisions: each approve, deny, or follow-up decision requires interactive PAM authentication. The package installs the `mayi-approve` PAM service at `/etc/pam.d/mayi-approve`, including the host's common authentication and account policies. Log out and back in (or otherwise refresh the account's supplementary groups) after membership changes, then verify the effective groups before use. Check package group IDs for collisions before deployment. Do not weaken the host's PAM policy to make approval succeed.

## Requester workflow

A synchronous request waits for the human decision and command result:

```sh
mayi /usr/bin/systemctl reload nginx
```

The executable must resolve to a root-owned, executable, non-group/world-writable file directly under one of `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, or `/bin`. Absolute paths are clearest; a command name can be resolved through Mayi's fixed search directories. Mayi bounds the full argv to 128 entries, 1,024 UTF-8 bytes per entry, and 2,048 bytes total.

### Processes, not shell strings

Mayi approves processes, not shell command strings. The calling shell performs its normal quoting and expansion before Mayi receives the arguments. Once passed to Mayi, metacharacters have no shell meaning by themselves:

```sh
mayi /usr/bin/printf '%s\n' 'hello world' '$HOME' '; rm -rf /'
```

Here `$HOME` and `; rm -rf /` are literal argument values. Mayi does not interpret `;`, `$`, `&&`, `|`, or `>` as shell syntax. A shell is involved only when the explicitly approved executable interprets code, for example:

```sh
mayi /bin/bash -c 'printf "%s\n" hello'
```

That is broad shell execution. The human must inspect the shell program and every other argument before approval.

### Queued requests and dependencies

Queueing returns an opaque ID; it is not approval or execution. Each command in a dependency chain needs its own human approval, and a child runs only after it is approved and all dependencies succeed.

```sh
d1=$(mayi --queue /usr/sbin/nginx -t)
d2=$(mayi --queue --after "$d1" /usr/bin/systemctl reload nginx)
d3=$(mayi --queue --after "$d2" /usr/bin/systemctl is-active nginx)

mayi --wait --fail=0 "$d1" "$d2" "$d3"
```

Use executable paths that exist on the machine; the example assumes nginx is installed and the service is already configured. `--after` must precede the executable and can be repeated. Dependencies must be retained queued requests owned by the same requester UID. Unknown, duplicate, invalid, non-queued, cyclic, and cross-requester dependencies are rejected. A terminal unsuccessful dependency blocks its descendants.

`--wait` observes results only: it does not approve, execute, cancel, or retry requests. Every terminal state other than `SUCCEEDED` consumes one unit of the `--fail=N` failure budget (default `0`). `--fail-instant` returns when observed failures exceed that budget; it does not cancel other requests. `--status ID` reports one job, and a successful status query does not mean the job succeeded. Queued requests are bounded and expire; queue and result persistence across broker restart is **NOT CLAIMED**. In practice, a broker restart loses in-memory queued state and results; no request is replayed.

## Approval workflow

Run one persistent console in the human approver's interactive terminal:

```text
$ mayi-approve
Waiting for Mayi requests...

[0] /usr/bin/systemctl reload nginx
Mayi > a
Password:
```

The console displays requests before decision authentication. A fresh PAM authentication prompt is shown for each approve, deny, or follow-up decision; there is no reusable authenticated console session. It presents the resolved executable, argv[0], remaining arguments, requester UID, request IDs, dependencies, and executor identity. For example, a command appears in this form (the state and IDs vary):

```text
Commands: 1
[0] /usr/bin/systemctl [argv0=/usr/bin/systemctl] (PENDING_APPROVAL)
     restart \
     nginx \
     requester UID: 1001
```

The arguments are separate display values, not shell input. Dependency chains are shown in topological order; linear dependencies use a downward arrow and branching dependencies list their prerequisite indices. The renderer does not turn its output back into an execution request.

### UI preview (not finally qualified)

The working-tree console refresh keeps the exact executable, argv[0], every argument,
requester UID, privileged executor identity, states, and dependency/blocking information
visible. Technical request/challenge IDs and digests are collapsed by default; press
**Space** at an empty main prompt to toggle them without making a decision. Actions
still require **Enter**. New arrivals show a notification rather than another set of
selectable indices; finish or skip the current set to review the updated queue.
This preview has not been packaged, deployed, or finally qualified.

Controls at the main prompt:

- `a`: allow all pending commands in the displayed connected set.
- `s`: skip that set for now; this is UI navigation only, not denial, and it may resurface.
- `d`: deny all or selected pending commands; denied commands do not execute.
- `f`: request follow-up for all or selected pending commands; no execution occurs and dependents cannot succeed.
- `y`, `n`, `e`: aliases for allow, deny, and follow-up.
- Numeric digits: select displayed command indices. **Current limitation:** indices are entered one decimal digit at a time, so numeric selection addresses indices 0–9 only. Use `a` when a displayed set contains higher indices; selecting individual indices above 9 is not supported by the current console.
- `q`: exit without deciding or cancelling pending requests.

After a fully correlated successful allow, deny, or follow-up decision, the console clears only the visible screen when stdout is a TTY and `TERM` is supported; it never erases scrollback. Failed decisions preserve the display. The console stays open and returns to waiting. See [`mayi-workflow(7)`](man/mayi-workflow.7) for the full operator procedure.

## Results and exit codes

The synchronous `mayi` command returns `0` on success, the approved child's output on the normal output streams, `10` on denial, `20` on follow-up, `11` on request expiry, `14` when the child exits unsuccessfully, `15` on an internal/execution-disabled result, and `16` when execution outcome is ambiguous. Usage/invalid request is `2` or `12`; authorization failure is `13`. `--wait` returns `0` within its failure budget and `1` when that budget is exceeded. See [`mayi(1)`](man/mayi.1) for mode-specific details.

Approved commands run with a cleared environment, fixed `PATH`, `LANG`, `LC_ALL`, and `HOME`, `/` as their working directory, and `/dev/null` as stdin. Captured output is bounded. Execution is at most once, not transactional: a command may partially change system state before it fails, and an ambiguous handoff is not retried. The executor does not impose a child runtime deadline.

## Known limitations and non-goals

- **Queue/result persistence across broker restart: NOT CLAIMED.** Queue state and results are in broker memory and are lost on broker restart.
- **Filesystem executor: DISCONNECTED / INCOMPLETE.** Structured filesystem operations are not enabled for privileged execution; do not treat filesystem-executor experiments as product functionality.
- Mayi does not determine whether an arbitrary approved program or its arguments are safe, provide transaction/rollback, or infer approval intent.
- `SO_PEERCRED` identifies an OS UID, not a process or a human. PAM authenticates the account entering the console; it does not distinguish processes sharing that account.
- **Synology DSM: NOT SUPPORTED.** The feasibility audit did not produce a port or installation path. Work is deferred pending target details and Synology's platform/security guidance.

## Supported systems

| Qualification | Result |
|---|---|
| Debian 11 Bullseye, 12 Bookworm, 13 Trixie | Supported runtime targets; candidate 0.4.1-5 exact artifact passed direct-systemd qualification; independent review remains required |
| Released architecture | `amd64` only |
| Capability-based runtime requirements | Linux Unix-domain `SO_PEERCRED` and `SCM_RIGHTS`; working NSS/PAM; systemd service cgroups with the broker at `/system.slice/mayi-broker.service`; PAM helper `CAP_DAC_READ_SEARCH` + `NoNewPrivileges`; required PAM-helper sandbox directives enforced |
| Ubuntu, Arch, Fedora, ARM/ARM64, Synology DSM, other systems | Not currently qualified; this is not a claim of incompatibility |

Debian 10 is excluded from supported runtime targets. The `openat2` path-resolution primitive is used only by the disconnected/incomplete filesystem executor; it is not on the enabled Mayi 0.4.1-5 execution path. systemd `RestrictSUIDSGID` is optional defense-in-depth for the PAM helper; effective confinement also relies on `NoNewPrivileges`, a `CAP_DAC_READ_SEARCH`-only capability set, filesystem protections, and the helper's no-command-execution design. Historical compatibility results do not override this policy. See [`DEBIAN_COMPATIBILITY.md`](DEBIAN_COMPATIBILITY.md) for evidence and limitations.

## Stable release and maintenance

- Stable feature baseline: **0.4.1**, release tag `v0.4.1`, release commit `9b3c69a292a36155d5994fa8b55da5cdc7f67ac4`.
- Published package revision: **0.4.1-1**, a packaging/documentation correction to maintainer/license metadata; the application/runtime remains 0.4.1. Publication and isolated APT consumer verification are recorded in [`MVP_QUALIFICATION.md`](MVP_QUALIFICATION.md).
- Qualified package: `executor/target/debian/mayi_0.4.1-1_amd64.deb`, SHA-256 `665d1154f7a0227ae93a5485c6ba493b57c18df856935e2611f8527270edb5d8`.
- The original qualified 0.4.1 package remains unchanged at `executor/target/debian/mayi_0.4.1_amd64.deb`, SHA-256 `22409abd977d4d14113ee34e47ed78f94a4e975da84e9606f5fe704116f59ab0`.
- Distribution: public TPA.run `bootstrap` repository through APT (see its signed [`InRelease`](https://tpa.run/r/tparun/bootstrap/dists/stable/InRelease) metadata). Publication is not deployment.

Release workflow at a high level: source → build on a portable baseline → qualify the exact `.deb` → record its SHA-256 → commit/tag → publish those exact bytes → verify an isolated APT consumer download. Detailed release and qualification records are in [`MVP_QUALIFICATION.md`](MVP_QUALIFICATION.md) and [`executor/package/README.md`](executor/package/README.md).

## Documentation

- [`man/mayi.1`](man/mayi.1): concise command reference.
- [`man/mayi-workflow.7`](man/mayi-workflow.7): requester/approver workflow and security expectations.
- [`ARCHITECTURE.md`](ARCHITECTURE.md): current component and trust-boundary overview.
- [`PROTOCOL.md`](PROTOCOL.md): current Protocol 5 message and lifecycle details.
- [`SECURITY_BOUNDARY.md`](SECURITY_BOUNDARY.md): current guarantees, trust assumptions, and non-goals.
- [`DEBIAN_COMPATIBILITY.md`](DEBIAN_COMPATIBILITY.md): OS compatibility and release qualification history.
- [`MVP_QUALIFICATION.md`](MVP_QUALIFICATION.md): immutable-version artifact, test, publication, and APT-consumer evidence.
- [`executor/package/README.md`](executor/package/README.md): package-specific operations, build inputs, and qualification harness.
- [`docs/FILESYSTEM_EXECUTOR_STATUS.md`](docs/FILESYSTEM_EXECUTOR_STATUS.md): current disabled/incomplete status; detailed historical research is indexed in [`docs/history/README.md`](docs/history/README.md).

## Development and maintenance

Feature development is paused. For a concrete bug or security report, include the affected version, reproduction steps, and whether the issue changes a documented guarantee. Runtime and packaging changes require explicit justification and appropriate requalification; a documentation-only cleanup must not be presented as a new feature release.

`pyproject.toml`, `mayi.__version__`, and `executor/Cargo.toml` describe internal Python/Rust source components; their component versions and development dependency requirements are not Mayi's Debian release version or runtime dependency floor. The Debian package metadata in `executor/package/tpa.json` and the qualified `.deb` define the released product.

Useful source checks (they do not build or publish a Debian package):

```sh
python3 -m pytest -q
cargo test --manifest-path executor/Cargo.toml --locked
cargo clippy --manifest-path executor/Cargo.toml --all-targets --all-features -- -D warnings
cargo fmt --manifest-path executor/Cargo.toml -- --check
```

The exact package build and qualification procedure is documented in the package README. Do not rebuild or republish either immutable package identity after qualification.

## Contact

General project and maintainer contact: [mayi@lupricht.net](mailto:mayi@lupricht.net).

For suspected security vulnerabilities, contact [mayi-security@lupricht.net](mailto:mayi-security@lupricht.net) privately. Do not file exploit details or other sensitive vulnerability information in a public issue. See [`SECURITY.md`](SECURITY.md).

## License

Mayi is licensed under the [MIT License](LICENSE).
