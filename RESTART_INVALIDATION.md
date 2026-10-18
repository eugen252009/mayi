# Restart invalidation

Broker state, views, console sessions and approvals are memory-only. A new
process cannot accept old instance-bound authority. The retained request-ID
provenance key DOES NOT restore authorization.

BROKER_STARTED is emitted after sockets are bound/nonblocking and initialization
has succeeded. Normal SIGTERM/SIGINT shutdown takes the same mutex as admission,
approval, consumption and queue claims, sets a private stopping fence and clears
console sessions. New authorization/claims fail BROKER_STOPPING. It emits
BROKER_STOPPING and per-request REQUEST_INVALIDATED records only for
unexpired pending/approved requests with Idle execution and no Running/terminal
queue state. State Consumed is NEVER classified safely invalidated, even if a
spawn observation is absent. Logging occurs after unlocking this shutdown snapshot.
The fence is internal shutdown behavior, not a public drain/admission API.

SIGKILL/crashes cannot promise a stopping record. A later trusted BROKER_STARTED
with another epoch can establish historical epoch invalidation by inference,
but never prove that an operation did not run. Existing real outcomes remain.
Lost journal records, missing results, timeouts or absent queue state do not
establish safe recreation. Explicit pre-claim invalidation evidence is distinct
from lifecycle inference in history JSON.

GET_QUEUE_STATUS authenticates v2 IDs before looking up RAM state or trusting an
optional broker_instance_id pin. Dependency IDs use the same check. An authentic
older ID gives BROKER_EPOCH_CHANGED; forged/unknown IDs do not. This is not a
bearer capability. There is no new by-rq execution/approval API: existing approval
and consumption remain exact challenge/digest/instance-bound, with no legacy
fallback. Explicit old challenge instance mismatches retain the protocol-5
BROKER_INSTANCE_MISMATCH alias, augmented with INVALIDATED/UNKNOWN/reconcile
metadata. This claim is weaker evidence than an authenticated rq_v2 mismatch.

Read-only current queue status retains existing ok/state terminal reads, adding
authorization_error: REQUEST_EXPIRED, AUTHORITY_DENIED, REQUEST_CONSUMED or
OUTCOME_UNKNOWN as applicable. It must still let waiters observe completion.
Consumption keeps ALREADY_CONSUMED as a compatibility flat code and adds
error.code REQUEST_CONSUMED; denied consumption similarly adds AUTHORITY_DENIED.
Expired consumption returns REQUEST_EXPIRED. Missing current state is not an
epoch change. Historical records are not used to re-authorize any request.

mayi --status ID prints the broker error and exits 16 for a proven epoch change.
mayi --status --json ID returns the correlated structured broker response and
exit 16. No retry, recreation, PAM invocation or approval migration occurs.
