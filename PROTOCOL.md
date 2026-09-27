# Mayi Protocol 5 — approval, status, and one-shot execution

## Security semantics

Protocol 5 separates request proposals from approval-authority messages. Client-supplied `approval`, `scope`, `decision`, `consumed`, or digest fields do not authorize anything. The request socket rejects fields outside exact schemas. The requester cannot choose challenge IDs, broker identity, or expiry, nor change a stored request during consume.

Rust authenticates requester and approver roles with `SO_PEERCRED`, stores the immutable request, creates a fresh 192-bit broker instance ID and 192-bit challenge ID, and enforces monotonic expiry. SHA-256 identifies request semantics; it is not approval evidence. Restarting the broker invalidates all pending/approved request state.

## Roles and framing

The package's default paths and role identities are:

| Role | Identity | Socket |
| --- | --- | --- |
| requester | Member of `mayi-requester` GID 23011 | `/run/mayi/request/broker.sock` |
| broker | UID/GID 23002/23012 | Request, approval, and executor client |
| approver | Member of `mayi-approver` GID 23013 | `/run/mayi/approval/broker.sock` |
| privileged executor | UID/GID 0/23012 | `/run/mayi/executor/executor.sock` |

The broker obtains PID, UID, and GID from `SO_PEERCRED`. It authorizes requester/approver roles by resolving that kernel UID through NSS (`getpwuid_r` plus `getgrouplist`), including primary and supplementary group membership, on every connection without caching. Peer-supplied GID, JSON, environment, and username are not authorization evidence. One user may belong to both role groups. The stored request and approval view still bind the actual peer UID; only that requester UID may consume its request. Socket group permissions remain defense in depth. The executor independently accepts only exact broker UID 23002. `SO_PEERCRED` authenticates an OS UID, not a process, executable, or human. NSS lookup failure is an internal error; an unknown or nonmember UID is rejected. Check package GIDs before host installation.

Broker request/approval sockets use four-byte big-endian length-prefixed UTF-8 JSON, up to 512 KiB, with a five-second broker transaction deadline. Each role has a bounded worker pool; excess connections are rejected. The executor uses the same framing with 64 KiB request and 300 KiB response caps. A broker-to-executor transaction may last up to 300 seconds; the `mayi` client waits up to 310 seconds for that one-shot response.

## Request shape and validation

A proposal has one operation and target metadata:

```json
{"type":"PROPOSE_REQUEST","protocol":5,"target":{"uid":1000,"gid":1000},"operations":[{"type":"exec","executable":"/usr/bin/systemctl","argv":["systemctl","reload","nginx"]}]}
```

For `exec`, the operation schema is exactly `type`, `executable`, and `argv`. The executable must be a canonical absolute path directly under `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, or `/bin`; its resolved file and path components must be root-owned, executable, and not group/world writable. The broker validates and stores the exact argv. Limits are 128 arguments, 1,024 UTF-8 bytes per argument, and 2,048 total argument bytes. Unknown or duplicate JSON keys, wrong types, embedded NULs, unsupported operations, and extra fields fail closed. Service/package operation strings are not accepted by the broker policy.

The request `target.uid/gid` fields are metadata for the stored proposal; they do not change the privileged child's identity. The approver sees both this metadata and actual execution identity UID 0, primary GID 23012.

The broker also recognizes the existing structured file operations, but their approved consume remains `EXECUTION_DISABLED`; they do not call the privileged executor or mutate the filesystem. The isolated filesystem core is not connected.

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

## Limitations

`SO_PEERCRED` does not attest human identity or protect against compromise of a trusted UID. Root-owned executables may still have dangerous semantics; the approval UI is not a semantic policy engine. The process launch is not transactional and provides no rollback. The filesystem executor remains disconnected and independently **INCOMPLETE**. Package 0.3.1 (native GLIBC_2.28 floor) passed disposable Debian 10–13 systemd qualification; Debian 13 additionally passed fresh install and upgrades from 0.2.0 through 0.3.0. The administrator subsequently reported manual deployment and a queue/approval smoke test on the real Debian 12.15 host; this consolidation did not access or modify it. Compatibility and EOL caveats are recorded in [DEBIAN_COMPATIBILITY.md](DEBIAN_COMPATIBILITY.md). Queue state is intentionally not durable across broker restart.
