# Porta recovery contract (documentation; no Porta changes)

Every integration retains the returned request/challenge ID, immutable epoch,
exact operation identity and explicit approval workflow. Persistent provenance
of an ID is not persistent authority.

* SAFE_TO_RECREATE_REQUEST: explicit trusted broker per-request pre-claim
  REQUEST_INVALIDATED / INVALIDATED / BROKER_STOPPING evidence, with a unique
  request binding and no contradictory claim/start/completion evidence.
  Recreate only deliberately after checking applicability; a new ID and fresh
  human authorization are mandatory. Never replay an approval.
* RECONCILIATION_REQUIRED: dispatch/consumption/start without a definitive result,
  crash/restart inference, missing audit, timeout, response loss, contradictory
  evidence, unauthenticated legacy identity or only BROKER_EPOCH_CHANGED.
  The latter proves old authority invalid, NOT absence of execution.
* COMPLETED: correlated authoritative terminal execution/lifecycle evidence,
  success or failure; it does not mean success or authorize retry of failed work.

mayi.recovery.classify_recovery is an evidence-only function operating on already
trusted, projected, uniquely correlated events. History uses it; neither broker,
PAM nor root executor imports its decisions. It performs no IPC, queue changes,
capability recovery, execution or retry. History JSON provides classification,
evidence source, authorization_state and execution_outcome separately.
The broker's authenticated epoch error supplies retryable=false and fresh
request/approval requirements, plus conservative execution UNKNOWN and
RECONCILIATION_REQUIRED. Consumers may not replace UNKNOWN with failed.

Current status is a separately authorized snapshot, not a historical recovery
database. Track broker epoch changes during reconnect; do not silently continue
old wait/approval workflows. No exactly-once side effects, execution-start TTL,
queue persistence, restart recovery or automatic retry is claimed.
