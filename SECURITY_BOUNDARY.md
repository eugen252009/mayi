# mayi security boundary — protocol v5 foundation status

## Implemented

- Python is an untrusted proposal client. Its policy and generated SHA-256 values grant no authority.
- Rust owns a bounded, in-memory immutable proposal/challenge store, generates broker-instance and challenge identities from `/dev/urandom`, binds requester UID from `SO_PEERCRED`, and owns expiry using monotonic time.
- Proposal and authority messages are distinct roles on separate Unix sockets. Production requires distinct requester, broker, and approver UIDs and distinct socket GIDs; `SO_PEERCRED` authenticates both roles. Socket files are broker-owned mode 0660. Parent/ancestor ownership and permissions are checked before stale-path handling and binding.
- Rust rejects duplicate JSON keys, unknown fields, invalid message schemas, unsupported operation types, and non-single-operation requests. Each broker-generated one-shot view binds instance, exact challenge, request digest, approver UID, and monotonic expiry. The renderer formats the stored request and visibly escapes terminal/bidi controls. Decisions must return the view ID and are correlated by the console.
- Approve, deny and explain consume the current view. Deny cannot be resurrected; explain leaves the request pending but invalidates its view. View replacement, expiry, immutable request binding, restart invalidation, and fabricated-view rejection are tested. The requester-side `CONSUME_APPROVED` request contains only broker instance, challenge, and digest; it authenticates `SO_PEERCRED`, atomically consumes the broker-held approved request once, and returns `CONSUMED / EXECUTION_DISABLED` without invoking an executor.
- Request and approval roles have separate eight-worker pools, five-second absolute transaction deadlines, bounded pending queues (128 global, 8 per requester), and overload rejection rather than unbounded connection queues. Cleartext view IDs are not logged; structured audit events use SHA-256 view references.
- Real-root, sudo, setuid, capabilities, filesystem mutation, fake-root mutation, stdio mutation, shell execution, services and packages remain disabled.

## Important qualification

The approval socket is an authenticated **UID role**, not process identity. A small Rust interactive console requires a TTY, authenticates the expected broker UID, obtains the broker-rendered challenge, and accepts exactly one framed `approve`, `deny`, or `explain`. It rejects trailing input, sends no decision on malformed input, flushes terminal input, and exits. It is not an independently audited production product. A process running as the configured approval UID can make decisions; the request UID is forbidden from being configured as that approver. The updated live qualification used requester/broker/approver UIDs `21001/21002/21003`, distinct role GIDs, plus unauthorized UID `21004`. Docker containers had dropped capabilities, read-only roots, and no network; the host Docker daemon was rootful, but no Mayi process ran as root. A rootless user-namespace attempt failed because `newuidmap` is unavailable. No host account or system configuration was changed. Therefore:

- Python cannot self-authorize by putting approval state or a digest in a proposal.
- Distinct-UID parser/consume qualification: **PASS** for the documented live matrix and PTY regressions; this is not a substitute for the targeted independent review.
- Same-UID process isolation: **NOT PROVIDED**; `--development-same-uid` is not a security deployment.
- Protection from a compromised process that can run as, or control, the configured approval UID: **NOT PROVIDED**.
- Trusted rendering source: Rust-held request; terminal-safe Rust approval console and strict input framing implemented, but independent trusted-UI assurance: **PENDING**.

## Remaining authorization-plane gate

- Run the targeted independent review of the Rust console parser, view/decision binding, requester/consume binding, multi-UID role separation, socket namespace, restart behavior, and execution-disabled handoff. The authorization plane is prepared for this re-audit; do not begin filesystem remediation before it passes.
- Same-UID socket substitution can alter displayed data in an unsafe development deployment, but the tested fake-broker view did not authorize the real broker. `SO_PEERCRED` does not distinguish same-UID processes.
- Finding-by-finding remediation of dormant filesystem execution defects remains a separate future milestone. Keep all execution unreachable until that work is separately repaired and audited.

## Current gate

The broker accepts protocol-v5 proposals, performs the approval ceremony, and supports a one-shot requester-side consume that always returns `EXECUTION_DISABLED`. Live distinct-UID tests covered the parser, all four modeled operations, role separation, restart, view lifecycle, and concurrent consumption; fixture contents and names remained unchanged. The authorization-plane completion milestone is **complete and ready for targeted independent re-audit**. Do not treat the plane as frozen or begin filesystem remediation until that review passes. Do not enable root or remove the execution-disabled result.
