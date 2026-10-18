# IPC protocol and integration

Protocol5 requester/approver sockets use four-byte big-endian length-prefixed
UTF-8 JSON, strict exact schemas/duplicate-key rejection and bounded frames.
Broker max frame512KiB. Descriptors are accepted only on specified TTY-bearing
approval/session paths; they are not requester-controlled execution input.
PAM helper has its own correlated protocol1; executor framing/request/response
bounds are separate. See [broker](../../executor/src/broker.rs),
[PAM](../../executor/src/pam_auth.rs) and [client](../../mayi/executor.py);
this summary does not license unspecified fields.

| Surface | Supported operations / purpose |
|---|---|
| /run/mayi/request/broker.sock | PROPOSE_REQUEST, GET_REQUEST_STATUS, CONSUME_APPROVED; QUEUE_REQUEST, GET_QUEUE_STATUS |
| /run/mayi/approval/broker.sock | LIST_PENDING, GET_CHALLENGE, bound approve/deny/follow-up decisions; AUTHENTICATE_CONSOLE, GET_CONSOLE_SESSION, END_CONSOLE_SESSION; read-only QUEUE_STATUS |
| /run/mayi/pam-auth/auth.sock | Trusted broker authentication/account checks, exact UID/correlation and controlling TTY |
| /run/mayi/executor/executor.sock | Trusted broker stored-operation execution and correlated optional spawn observation |

Requester/approver authorization is from kernel UID and NSS, not claimed JSON UID.
Decision/session messages require the specified single terminal descriptor.
QUEUE_STATUS is exactly protocol/type, no descriptors/selectors; it returns before
authorization cleanup/session mutation. It takes one lock/sample and cannot
approve, consume, renew or clean expired state. Session GET does not renew but
session internals can invalidate dead/expired sessions: it is not the same
side-effect-free aggregate status endpoint.

One proposal carries one exec operation: type, executable, argv. Target uid/gid
are stored metadata, not a privilege selector. Limits:128 argv entries,1024 UTF-8
bytes each,2048 bytes total. The client resolves against fixed trusted directories;
every argument after executable dispatch belongs to that executable unchanged.

New queued IDs are217-character authenticated rq_v2 identities:
rq_v2_<48hex epoch>_<32hex nonce>_<64hex digest>_<64hex MAC>.
They are provenance/lookup identifiers, NOT bearer capabilities. Legacy rq_32hex
is readable historical syntax, not newly issued authenticated epoch evidence.
An authentic stale ID yields BROKER_EPOCH_CHANGED, retryable=false, requires new
request/approval, execution UNKNOWN. Reconciliation precedes any deliberate new
operation. There is no rq-ID execution shortcut. For full binding/key/error
details see [epochs](../../BROKER_EPOCH.md) and [restart](../../RESTART_INVALIDATION.md).

Native audit schema1, history JSON schema2, ordinary live snapshot schema1 and
preflight additions schema1 remain independent contracts. See
[history schema](../../HISTORY_SCHEMA.md), [status schema](../../STATUS_JSON_SCHEMA.md),
[counter mapping](../../QUEUE_STATE_MAPPING.md), [preflight](../../UPDATE_PREFLIGHT.md).
Human status/history formatting is not machine authority.

A queued dependency is another retained request of the same kernel-authenticated
requester. Queue capacity128 retained records, at most8 active per requester.
Wait/status observe, never approve/cancel/replay. Child dispatch requires accepted
approval plus successful prerequisites. Retention is not restart persistence.

Porta/other clients use these same authenticated boundaries. No Porta files or
recovery integration are changed here. [Porta recovery contract](../../PORTA_RECOVERY_CONTRACT.md)
is evidence-only guidance, not automatic resubmission authority. A protocol/source
disagreement must be investigated, not resolved by expanding accepted schemas.
