# Mayi Protocol 5 — approval, status, and one-shot execution

> **Development 0.4.1-9~ui3:** explicit, broker-enforced five-minute sliding console authentication sessions are now implemented. Successful decisions renew the window; reads do not. This supersedes per-decision password claims below for the new console only. Legacy clients still use per-decision PAM. See [AUTHENTICATION_SESSIONS.md](AUTHENTICATION_SESSIONS.md) for protocol, threat-model changes and test limits. Not packaged, deployed or production-qualified.

## Security semantics

Protocol 5 separates request proposals from approval-authority messages. Client-supplied `approval`, `scope`, `decision`, `consumed`, or digest fields do not authorize anything. The request socket rejects fields outside exact schemas. The requester cannot choose challenge IDs, broker identity, or expiry, nor change a stored request during consume.

**Release scope:** the broker-side PAM authority and `SCM_RIGHTS` decision flow below describe candidate 0.4.1-5. Its exact artifact passed direct-systemd qualification on supported Debian 11–13 and is ready for independent security review, not production use or publication. Debian 10 is not a supported runtime target. Published 0.4.1 enforces PAM in the supplied console client, not in the broker protocol; a direct approval-socket client can bypass that PAM gate.

Rust authenticates requester and approver roles with `SO_PEERCRED`, stores the immutable request, creates a fresh 192-bit broker instance ID and 192-bit challenge ID, and enforces monotonic expiry. SHA-256 identifies request semantics; it is not approval evidence. Restarting the broker invalidates all pending/approved request state.

## Roles and framing

The package's default paths and role identities are:

| Role | Identity | Socket |
| --- | --- | --- |
| requester | Member of `mayi-requester` GID 23011 | `/run/mayi/request/broker.sock` |
| broker | UID/GID 23002/23012 | Request, approval, and executor client |
| approver | Member of `mayi-approver` GID 23013 | `/run/mayi/approval/broker.sock` |
| PAM authentication authority | UID/GID 0/23012; accepts only broker UID 23002 from the fixed broker systemd cgroup | `/run/mayi/pam-auth/auth.sock` |
| privileged executor | UID/GID 0/23012 | `/run/mayi/executor/executor.sock` |

The `mayi-approve` console requires an interactive controlling TTY. For every decision, its approval-socket request carries exactly one terminal descriptor using `SCM_RIGHTS`; no password, reusable token, or client assertion is sent. The unprivileged broker first verifies the kernel peer UID against NSS membership in `mayi-approver` and validates the active request/view, then forwards the broker-derived UID, operation, broker instance, challenge, digest, view ID, and terminal descriptor to the separate PAM authority. That service runs as UID 0/GID 23012 because Debian `pam_unix` cannot authenticate a different local UID from an unprivileged process. Its capability bounding/effective sets contain only `CAP_DAC_READ_SEARCH`; it also uses `NoNewPrivileges`, strict systemd filesystem protections, and narrowly scoped writable runtime paths. It accepts only broker UID 23002 when `/proc/<pid>/cgroup` places the peer in `/system.slice/mayi-broker.service`. The helper intentionally does not inspect `/proc/<pid>/exe` because it lacks `CAP_SYS_PTRACE`; the cgroup is the systemd-managed service identity. The helper validates the request shape, resolves the claimed UID through NSS, and authenticates that account with PAM service `mayi-approve`, including `pam_acct_mgmt`. The broker rechecks NSS role membership and decision state after PAM succeeds and immediately before the transition. The helper's conversation supports echo-off and echo-on prompts, sanitizes terminal text, clears secret buffers, and fails closed on unsupported prompts, timeout, locked/ineligible accounts, descriptor or terminal errors, and malformed helper responses. Each decision gets fresh PAM authentication; no session/result is reusable. Direct protocol clients cannot bypass PAM; a decision without a terminal descriptor returns `PAM_AUTH_REQUIRED`. The helper's cgroup path is fixed and systemd-specific; customization or non-systemd operation fails closed.

The broker obtains PID, UID, and GID from `SO_PEERCRED`. It independently authorizes requester/approver roles by resolving that kernel UID through NSS (`getpwuid_r` plus `getgrouplist`), including primary and supplementary group membership, without trusting peer-supplied GID, JSON, environment, or username. The broker rechecks approver membership after PAM authentication before applying a decision. One user may belong to both role groups. The stored request and approval view bind the actual peer UID; only that requester UID may consume its request. Socket group permissions remain defense in depth. The helper accepts only broker UID 23002 from the protected broker service cgroup, and the executor independently accepts only that UID. `SO_PEERCRED` authenticates an OS UID, not a binary or human. The cgroup check rejects an out-of-service same-UID process from the PAM authority, but the broker service and host root/systemd administration remain trusted; it is not protection against a compromised broker or privileged service manager. NSS lookup failure is an internal error; an unknown or nonmember UID is rejected. Check package GIDs before host installation.

Broker request/approval sockets use four-byte big-endian length-prefixed UTF-8 JSON, up to 512 KiB, with a five-second broker transaction deadline for ordinary messages. Approval decisions may carry one `SCM_RIGHTS` terminal descriptor attached to the frame header; descriptors on other message types or in the body are rejected. The broker-to-PAM socket has a separate bounded, strict JSON protocol, verifies its `SO_PEERCRED` peer, correlates the full decision tuple in both directions, and applies a 300-second authentication deadline. Each role has a bounded worker pool; excess connections are rejected. The executor uses the same framing with 64 KiB request and 300 KiB response caps. A broker-to-executor transaction may last up to 300 seconds; the `mayi` client waits up to 310 seconds for that one-shot response.

## Request shape and validation

A proposal has one operation and target metadata:

```json
{"type":"PROPOSE_REQUEST","protocol":5,"target":{"uid":1000,"gid":1000},"operations":[{"type":"exec","executable":"/usr/bin/systemctl","argv":["systemctl","reload","nginx"]}]}
```

For `exec`, the operation schema is exactly `type`, `executable`, and `argv`. The executable must be a canonical absolute path directly under `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, or `/bin`; its resolved file and path components must be root-owned, executable, and not group/world writable. The broker validates and stores the exact argv. Limits are 128 arguments, 1,024 UTF-8 bytes per argument, and 2,048 total argument bytes. Unknown or duplicate JSON keys, wrong types, embedded NULs, unsupported operations, and extra fields fail closed. Service/package operation strings are not accepted by the broker policy.

The request `target.uid/gid` fields are metadata for the stored proposal; they do not change the privileged child's identity. The approver sees both this metadata and actual execution identity UID 0, primary GID 23012.

The live broker rejects structured filesystem proposals with `UNSUPPORTED_OPERATION` before creating pending state (0.4.1-7 remediation). They cannot be approved, queued or consumed. Accepting these disconnected operations previously poisoned the exec-only approval console. Validation-only/direct filesystem tests remain separate; the filesystem core is not connected.

Expiration uses process-local monotonic deadlines (300 seconds for ordinary proposals; the existing queued lifetime remains 24 hours). Under the broker mutex, the selected request's final monotonic clock read immediately before its one-way consumption/queue-dispatch transition is the authorization linearization point. Equality with the deadline is expired. The preliminary sweep is housekeeping, not authority. Approval also revalidates both request and view deadlines after PAM. Time spent before this final sample, including scheduling and IPC/authentication delays, cannot extend eligibility. This is a consumption-time validity guarantee, not an execution-start or response-delivery deadline; Linux monotonic time does not claim suspend-inclusive expiry.

A successful claim may be dispatched or start execution later, including after its displayed expiration. `UNKNOWN` is not cancellation: a command may not have started yet and may start later. Do not automatically retry, replay or requeue uncertain execution. Broker restart invalidates old authority, not already dispatched work. At-most-once authorization is not exactly-once execution or effects.

## Approval and one-shot lifecycle

The broker stores the immutable request before returning `PENDING_APPROVAL`, `broker_instance_id`, `challenge_id`, `request_digest`, and informational wall-clock expiry. Rust enforces the five-minute request deadline with monotonic time.

The approval console lists pending requests, fetches a fresh broker-generated one-shot view, verifies the peer broker UID and challenge/digest correlations, and accepts the synchronous `y`, `n`, or `e` decisions (legacy `approve`, `deny`, `explain` decision names are internal authority messages). It is a persistent interactive console; for queued requests it groups connected dependency DAGs, renders exact executable/argv and dependencies with topological indices, refreshes arrivals, and accepts `a/s/d/f`, aliases `y/n/e`, numeric selection, or `q`. Skip changes only local console navigation. Each decision still uses a fresh one-shot view bound to the approver UID. `y` approves one synchronous consume; queue approval authorizes only the immutable stored queued operation. `n` is terminal denial and `e` requests follow-up without approval. A view lasts at most one minute and is invalidated by a later fetch or decision.

The requester polls with the exact `GET_REQUEST_STATUS` tuple:

```json
{"type":"GET_REQUEST_STATUS","protocol":5,"broker_instance_id":"…","challenge_id":"…","request_digest":"…"}
```

Only the original requester UID can read status or consume. After `APPROVED`, it sends only that same tuple as `CONSUME_APPROVED`; no executable or argv is accepted on consume. Under the broker lock, Rust changes `APPROVED → CONSUMED` once, selects the stored operation, releases the lock, and sends a fixed `EXEC_REQUEST` to the separate executor. The executor authenticates broker UID 23002, validates the same executable/argv bounds and executable trust rules, clears the environment, uses `/` cwd and `/dev/null` stdin, and spawns without shell mediation. Environment is fixed to `PATH`, `LANG`, `LC_ALL`, and `HOME`; stdout/stderr are drained and capped at 64 KiB each.

The executor durably journals the broker-derived one-shot request ID before spawning. Duplicate or uncertain journal claims never spawn again; duplicate request IDs return an unknown execution outcome. Broker/executor communication failure after consume is not retried. The broker waits at most 300 seconds, but the child itself has no runtime deadline; if it runs longer, the client reports execution unknown while the executor may still be waiting, and its single-threaded service will not accept another request until that child exits. Therefore a lost response can mean the command ran, and the client never risks a second invocation. A completed nonzero child exit is `MAYI_EXECUTION_FAILED` (exit 14); transport/authorization failure, denial, explain, expiry, and unknown execution have stable separate exit codes documented in the package README.

## Asynchronous queued execution

`QUEUE_REQUEST` is additive to the existing blocking `PROPOSE_REQUEST` flow and accepts exactly one `exec` operation plus a dependency array:

```json
{"type":"QUEUE_REQUEST","protocol":5,"target":{"uid":1000,"gid":1000},"dependencies":["rq_<32-lowercase-hex>"],"operations":[{"type":"exec","executable":"/usr/bin/systemctl","argv":["/usr/bin/systemctl","reload","nginx"]}]}
```

Rust generates a unique opaque `rq_<32 lowercase hex>` ID and returns it immediately. IDs are not request digests or client-selected. The stored executable/argv cannot be edited. Every dependency must refer to a retained queued request from the same kernel-authenticated requester UID; duplicate/unknown IDs, non-queued parents, cycles, and cross-requester dependencies are rejected. Dependencies are immutable at submission, so an ordinary client cannot construct a cycle, but the broker still checks the graph. Queue size is bounded globally and per active requester; queued approvals expire after 24 hours.

The persistent console presents connected DAGs in topological order. Numeric approval sets are normalized into display order; partial approval leaves unselected jobs untouched. The broker dispatches an approved job at most once, and only after all dependencies report `SUCCEEDED`. If any dependency reaches a terminal non-success state, descendants become `BLOCKED` and do not execute. Denial and follow-up remain terminal human decisions. `GET_QUEUE_STATUS` is bound to the original requester UID and returns state/result metadata for the opaque ID. `mayi --wait` only observes; its failure budget counts every terminal state other than `SUCCEEDED`, and `--fail-instant` returns once that budget is exceeded without cancelling any job. `mayi --status` reads one result.

Queue state and results are held in broker memory only. Broker restart invalidates queued approvals and status/result history; no pending request is replayed, no execution is retried, and restart-safe queue retention is not claimed. Results remain queryable within the live broker's bounded retention window (up to 24 hours). The privileged executor journals each queue ID-derived one-shot dispatch before spawning, retaining the existing replay protection.

Non-`exec` filesystem operations remain `CONSUMED / EXECUTION_DISABLED`. `Exec` is the only privileged operation enabled by this MVP. No shell command string, requester environment, arbitrary descriptor, or second consume payload is accepted. The MVP is intentionally broad: a human who approves an explicitly requested executable (including a shell binary if one is requested) is authorizing that executable and argv as root.

## Limitations and release status

`SO_PEERCRED` identifies an OS UID, not a process or human, and does not protect against compromise of a trusted UID. Root-owned executables may have dangerous semantics; the approval UI is not a semantic policy engine. Execution is at most once but not transactional and has no rollback. The filesystem executor remains disconnected and independently **INCOMPLETE**; non-`exec` filesystem operations return `EXECUTION_DISABLED`.

Queue state and results are held in broker memory. Persistence across broker restart is **NOT CLAIMED**; pending queue state and retained results are lost on restart and are not replayed. The executor's durable one-shot journal does not make queue state persistent.

Mayi **0.4.1** remains the current published stable baseline. Candidate **0.4.1-5** adds broker-verifiable per-decision PAM authentication to address the 0.4.1-2 approval bypass. Its exact-artifact package matrix passed on supported Debian 11–13 and it is ready for independent security review; do not treat it as production-ready or published. Candidate 0.4.1-3's unprivileged PAM failure is documented separately. The retained 0.4.1-2 artifact remains unchanged and unpublished. Publication is not deployment. Debian 10 is not a supported runtime target; it was used as a build baseline and for historical qualification only. See [DEBIAN_COMPATIBILITY.md](DEBIAN_COMPATIBILITY.md) and [MVP_QUALIFICATION.md](MVP_QUALIFICATION.md) for the current policy and qualification evidence.
