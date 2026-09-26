# mayi protocol v5 — approval and disabled-consume lifecycle

## Security semantics

Protocol 5 separates `PROPOSE_REQUEST` from authority messages. Protocol 4 request documents, including `approval`, `scope: once`, or client-computed SHA-256 values, are not authorization. The request socket rejects fields outside its exact proposal schema. `approved`, `approval`, `scope`, `decision`, and `consumed` are never proposal fields.

A client digest is only an integrity/identity value. Rust constructs the canonical request after obtaining requester UID from `SO_PEERCRED` and adding its own broker instance ID, challenge ID, target UID/GID, and expiry. Rust generates a fresh 192-bit random broker ID at startup and a per-instance unique challenge ID containing 128 bits of fresh random entropy plus a monotonic counter. Challenges are held only in memory; restarting the broker changes the instance ID and discards every request and approval.

## Interfaces

Start the unprivileged broker with distinct requester/broker/approver UIDs, distinct socket groups, and two different paths:

```text
mayi-executor --request-socket REQUEST.sock --request-uid REQUEST_UID \
  --request-gid REQUEST_GID --approval-socket APPROVAL.sock \
  --approval-uid APPROVER_UID --approval-gid APPROVAL_GID
```

The broker refuses EUID 0, requires the broker UID to differ from both roles, requires requester and approver UIDs to differ, and requires distinct role groups outside explicit development mode. Socket paths must be under broker-owned non-writable directories; ancestors must be root/broker-owned and non-writable, except root-owned sticky directories. Socket files are mode 0660 and assigned to the configured role GID. The broker uses `SO_PEERCRED` for both roles. `--development-same-uid` allows only requester UID = broker UID; it is not a production isolation mode. The Rust console is launched as `mayi-executor --approval-console --approval-socket APPROVAL.sock --broker-uid BROKER_UID` and requires an unprivileged interactive TTY.

Both interfaces use 4-byte big-endian length-prefixed UTF-8 JSON, maximum 512 KiB, and a five-second absolute transaction deadline. Each role has a bounded eight-worker pool; excess connections are dropped instead of accumulating in an unbounded queue. Rust rejects duplicate JSON object keys at every nesting level, unknown fields, wrong types, non-integral identities, unsupported operation types, and proposals with other than one operation. Supported proposal operations are exactly `file_patch`, `file_create`, `file_delete`, and `file_move`. Operation size is capped at 128 KiB; pending storage is capped at 128 entries and eight active requests per requester; render output is capped at 32 KiB; broker-owned lifetime is five minutes; view lifetime is at most one minute.

## Messages and lifecycle

Request role:

```json
{"type":"PROPOSE_REQUEST","protocol":5,"target":{"uid":1000,"gid":1000},"operations":[...]}
```

The client supplies neither request/challenge IDs nor expiry, requester identity, nor decision state. A successful response gives `broker_instance_id`, `challenge_id`, `request_digest`, `PENDING_APPROVAL`, and a human-readable expiry. Rust stores the immutable semantic request before returning that response.

After approval, the original requester may send this exact request-side message:

```json
{"type":"CONSUME_APPROVED","protocol":5,"broker_instance_id":"…","challenge_id":"…","request_digest":"…"}
```

No view ID or operation semantics are accepted. Rust authenticates the socket peer with `SO_PEERCRED`, checks that it is the stored requester, verifies instance/challenge/digest and the original monotonic deadline, and atomically transitions only `APPROVED → CONSUMED`. The success response reports `state: CONSUMED` and `execution: EXECUTION_DISABLED`; no executor is called. Replays return `ALREADY_CONSUMED`. DENIED, EXPLAINED-but-not-approved, pending, expired, wrong-role, and wrong-instance requests cannot be consumed.

Approval role supports `LIST_PENDING`, `GET_CHALLENGE`, `APPROVE_CHALLENGE`, `DENY_CHALLENGE`, and `EXPLAIN_CHALLENGE`. Every `GET_CHALLENGE` creates a fresh unpredictable one-shot `view_id` bound in broker memory to broker instance, exact challenge, request digest, approver UID, and monotonic expiry. A new fetch invalidates prior views for that challenge. The returned rendering is generated atomically from the Rust-held immutable request, with terminal/bidi controls escaped. The Rust console verifies broker instance, challenge, digest, pending state, view ID shape, and view expiry, then sends the exact correlated view ID with the chosen decision. Decisions consume the view; approve transitions pending to approved, deny is terminal, and explain leaves the request pending but consumes that view. The view ID is not logged in cleartext (audit logs store its SHA-256 reference). Python changes always require a new proposal/challenge.

Pending and approved validity is measured with Rust `Instant` monotonic time; `expires_at` is informational wall-clock time. Expiry transitions pending/approved requests to expired. Consumption must occur before the original five-minute challenge deadline; an approval does not extend that deadline. Broker memory is ephemeral, so restart invalidates pending, approved, and unconsumed challenge state. Protocol 5 remains unchanged because `CONSUME_APPROVED` is an additive request-role message: existing proposal/approval clients remain safe, while only upgraded request clients can perform the disabled handoff.

## Digest and renderer

The SHA-256 digest is canonical request integrity only, never proof of approval. It covers protocol, broker instance, challenge, requester UID, target UID/GID, expiry, and the complete single operation semantics. The renderer draws exclusively from the stored request; paths, patch old/new edits, create content, hashes, operation type, mode, identities, IDs, and expiry are included as applicable. ANSI/control characters, line breaks, bidi formatting controls, and selected zero-width controls are encoded visibly. Renderer output is bounded. A client-supplied description or diff is not accepted.

## Execution boundary

Approval does not enable execution. A requester-side wire consume deliberately transitions an approved request to `CONSUMED` and reports `EXECUTION_DISABLED`; this is a temporary pre-execution qualification semantic, not a grant to execute later. Filesystem mutation, fake-root mutation, real-root execution, `Exec`, service/package operations, stdio submission, setuid, setgid, sudo, and capabilities remain disabled. Stdio returns `APPROVAL_SOCKET_REQUIRED`; it cannot propose, approve, consume, or mutate.

The Rust approval console is available via `--approval-console --approval-socket PATH --broker-uid UID`. It requires an unprivileged interactive TTY, authenticates the expected broker UID, and validates all challenge/view correlations. Decision grammar is exactly lowercase `approve`, `deny`, or `explain`, followed by one line terminator; there are no decision aliases, whitespace trimming, or fuzzy matches. The bounded raw-TTY frame is at most 64 bytes. Input after the terminator during a 100 ms quiet window is rejected and drained; the terminal input queue is flushed and the console exits. A terminal's standalone Enter/CR is translated to LF by the configured line discipline. A pasted CRLF pair produces extra logical input and is rejected. Malformed input sends no approval message; the view remains displayed until expiry or a later GET replaces it. The selection prompt uses the same framed-input boundary, preventing queued decision text from crossing prompts. Input is not echoed. Same-UID processes are not isolated by `SO_PEERCRED`; do not use development mode as a production boundary.
