# mayi security boundary — protocol v5 foundation status

## Implemented

- Python is an untrusted proposal client. Its policy and generated SHA-256 values grant no authority.
- Rust owns a bounded, in-memory immutable proposal/challenge store, generates broker-instance and challenge identities from `/dev/urandom`, binds requester UID from `SO_PEERCRED`, and owns expiry using monotonic time.
- Proposal and authority messages are distinct roles on separate Unix sockets. Production requires distinct requester, broker, and approver UIDs and distinct socket GIDs; `SO_PEERCRED` authenticates both roles. Socket files are broker-owned mode 0660. Parent/ancestor ownership and permissions are checked before stale-path handling and binding.
- Rust rejects duplicate JSON keys, unknown fields, invalid message schemas, unsupported operation types, and non-single-operation requests. Each broker-generated one-shot view binds instance, exact challenge, request digest, approver UID, and monotonic expiry. The renderer formats the stored request and visibly escapes terminal/bidi controls. Decisions must return the view ID and are correlated by the console.
- Approve, deny and explain consume the current view. Deny cannot be resurrected; explain leaves the request pending but invalidates its view. View replacement, expiry, immutable request binding, restart invalidation, fabricated-view rejection, and an atomic one-shot consume method are tested. The consume method is internal/test exercised and always returns `EXECUTION_DISABLED`.
- Request and approval roles have separate eight-worker pools, five-second absolute transaction deadlines, bounded pending queues (128 global, 8 per requester), and overload rejection rather than unbounded connection queues. Cleartext view IDs are not logged; structured audit events use SHA-256 view references.
- Real-root, sudo, setuid, capabilities, filesystem mutation, fake-root mutation, stdio mutation, shell execution, services and packages remain disabled.

## Important qualification

The approval socket is an authenticated **UID role**. A small Rust interactive console requires a TTY, authenticates the expected broker UID, obtains the broker-rendered challenge, displays it, and offers approve/deny/explain. It is development UI, not an independently audited production product. A process running as the configured approval UID can make decisions; the request UID is forbidden from being configured as that approver. Cross-UID account/socket permissions and full console-to-decision flow have not been qualified. A rootless user-namespace attempt failed because `newuidmap` is unavailable; no privileged command, account change, or host-file change was made. Therefore:

- Python cannot self-authorize by putting approval state or a digest in a proposal.
- Distinct-UID deployment qualification: **INCOMPLETE / NOT EXERCISED**.
- Same-UID process isolation: **NOT PROVIDED**; `--development-same-uid` is not a security deployment.
- Protection from a compromised Python process that can run as, or control, the configured approval UID: **NOT PROVEN**.
- Trusted rendering source: Rust-held request; terminal-safe Rust approval console implemented, but full trusted-UI assurance: **PARTIAL**.

## Remaining blockers

- Exercise three distinct unprivileged UIDs and separate socket groups, verifying requester-to-approval path denial, broker ownership, stale-path handling, and complete console-to-decision correlation.
- Independently review the Rust approval console, socket lifecycle, and configuration ownership. Client peer-UID checks do not distinguish a malicious broker process sharing the broker UID.
- Run adversarial live socket-substitution, slow-client saturation/recovery, replay-after-process-restart, and concurrent approve/deny tests in the intended deployment.
- Finding-by-finding remediation of dormant filesystem execution defects. The old executor implementation remains in source but is unreachable from the new protocol and must not be re-enabled until separately repaired and audited.

## Current gate

The broker accepts protocol-v5 proposals and returns `PENDING_APPROVAL`; an approved challenge cannot invoke filesystem execution. The one-shot view ceremony and bounded worker/socket hardening are implemented but not fully qualified. Do not enable root or remove the execution-disabled result. This milestone is **incomplete** and is not ready for filesystem remediation or an end-to-end trusted-human-approval claim.
