# Event lifecycle and service responsibilities

Broker:
- PROPOSED: validated pending request object (not execution authority); queued Request-ID already exists.
- QUEUE_SUBMITTED: accepted queue mapping.
- VIEW_CREATED / VIEW_REPLACED / VIEW_EXPIRED: view lifecycle. VIEW_EXPIRED can mean deadline or invalidation by request state; it does not assert request expiration.
- VIEW_APPROVED / VIEW_DENIED / VIEW_EXPLAINED: accepted explicit decision, after existing PAM/session/NSS/view/request deadline gates.
- EXPIRED: authoritative request expiration.
- CONSUMED: synchronous one-way capability consumption.
- QUEUE_DISPATCH_STARTED: queue's locked RUNNING dispatch claim, NOT evidence that an OS child has spawned.
- QUEUE_EXECUTION_FINISHED: broker observed a correlated completed execution result.
- QUEUE_DISPATCH_FAILED: inability to dispatch/start, including observed spawn rejection.
- QUEUE_EXECUTION_OUTCOME_UNKNOWN: outcome is unknown; the child may still run.
- QUEUE_BLOCKED: failed/missing dependency; no execution success implied.
- EXECUTION_DISPATCH_STARTED / EXECUTION_FINISHED / EXECUTION_DISPATCH_FAILED / EXECUTION_OUTCOME_UNKNOWN: analogous synchronous handoff/result, without fabricated queue IDs.
- REQUEST_REJECTED, CONNECTION_ERROR/REJECTED, ROLE_LOOKUP_FAILED: bounded diagnostics. Correlate only with a known matching server request where available.
- CONSOLE_SESSION_AUTHENTICATED / INVALIDATED / REVOKED: session metadata only, not approval of any request.

PAM helper: PAM_AUTHENTICATION_FINISHED or PAM_ACCOUNT_CHECK_FINISHED (distinct operations), PAM_AUTH_PEER_REJECTED, PAM_AUTH_REQUEST_REJECTED, PAM_TERMINAL_RESTORE_FAILED. No password, conversation response, session token or view nonce is logged. Authentication success is not execution success.

Privileged executor: EXECUTOR_READY/STOPPED; EXECUTION_STARTED only after actual child spawn; EXECUTION_FINISHED only after a known completed wait/output result; EXECUTION_OUTCOME_UNKNOWN otherwise; EXECUTION_REJECTED for claim/spawn rejection and REQUEST_REJECTED for connection/protocol errors. Signal and normal exits are distinct. Existing durable one-shot claim ledger is unchanged; it is not replaced by Journald.

No request-cancel protocol exists. A client disconnect or UI cancellation does not automatically cancel an accepted operation; no fictional REQUEST_CANCELED event was added.

Compatibility: event=NAME remains in bounded MESSAGE, with a useful field subset. Old path hashes/dependency debug arrays are not duplicated, mayi_result becomes result, optional debug wrappers disappear. Former QUEUE_EXECUTION_STARTED was pre-spawn scheduling: it is deliberately renamed QUEUE_DISPATCH_STARTED. Unknown outcomes are no longer mislabeled "finished." Native fields, not MESSAGE parsing, are the supported filter interface.

Logging occurs after existing transition/claim points, never between a final deadline sample and its grant. Broker's private completion-observation flag affects only event naming; no wire schema, request identity, return result, authorization, retry or execution decision changes.
