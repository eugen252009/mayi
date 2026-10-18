# Broker epoch and request identifiers

The existing broker_instance_id IS the epoch: 24 bytes from /dev/urandom,
hex encoded, newly generated on every process start. There is no sequence,
timestamp-derived identity, persisted epoch or second UUID. Entropy failure
fails startup; cryptographic collision resistance (192 bits), not a mathematical
claim about arbitrary machine snapshots, underlies uniqueness.

Requests retain their originating instance through transitions. Approval views,
PAM challenges, console sessions, consumption and request digests already bind
this identity. New executor messages carry the originating instance as optional
validated 48-hex metadata, forwarded on started/finished/rejected native records.
Legacy executor messages remain accepted without invented epoch metadata.
The metadata does not grant execution; existing authenticated broker transport,
trusted executable rules and root one-shot claim remain authoritative.

## Authenticated rq_v2 identity
New queued requests use 217 ASCII characters:
rq_v2_<epoch:48hex>_<random-nonce:32hex>_<request-digest:64hex>_<MAC:64hex>.

MAC = HMAC-SHA256(key, ASCII("mayi.request.v2\\0") || epoch[24] ||
nonce[16] || request-digest[32]); the domain ends with one NUL, not the printed
backslash notation. Fixed byte widths make this unambiguous. The digest is
SHA256 of the existing recursively key-sorted JSON canonical request identity:
epoch, random challenge, dependencies, expiration, exact operations, protocol,
requester and target IDs. Nonce entropy is independently 128 bits. The existing
sha2 dependency implements SHA256; the fixed-32-byte RFC2104 HMAC construction
has an independent Python known-answer test; no new dependency is introduced.

Only the provenance key persists, in /var/lib/mayi-broker/request-id.key.
systemd StateDirectory=mayi-broker creates owner-private 0700 storage.
The broker atomically links a fully written/fsynced 0600 key, never overwrites
an existing key and validates file type, owner, permissions, nlink and length
with O_NOFOLLOW. Startup fails closed on unsafe/partial existing keys.
The key is never in IDs, audit metadata, argv, packages or source.
Remove/reinstall retains it; explicit dpkg purge deletes it. Losing/rotating it
means older IDs cannot be authenticated: REQUEST_NOT_FOUND, never a guessed
epoch-change error. This key authenticates provenance only: no pending request,
approval, view, capability or consumed authority is restored.

A valid MAC with a different epoch produces BROKER_EPOCH_CHANGED with
request_id, old epoch_id, current broker_instance_id, execution_outcome UNKNOWN,
and error {code,request_id,retryable:false,requires_new_request:true,
requires_new_approval:true}. Reconciliation still precedes any new operation.
A forged MAC returns REQUEST_NOT_FOUND. Bad shape gives INVALID_REQUEST_ID.
A valid current-epoch MAC does not recreate missing state.
Legacy rq_32hex identifiers remain history/read syntax, never authenticated
epoch evidence and are not newly issued. Unsupported versions fail closed.

New queue execution IDs use the first 16 bytes of
SHA256("mayi.execution.v2\\0" || full rq_v2 ID), as hex, retaining the existing
root ledger format and bounds. Legacy mappings remain unchanged. Broker audit
records provide explicit joins; history does not guess this mapping.

## Virtual history
Native schema 1 keeps MAYI_BROKER_INSTANCE_ID as the single persisted epoch
identity. History JSON schema 2 adds epoch_id (an alias of this recorded field),
authorization_state, invalidation evidence, execution outcome and recovery
classification. No decorative separator is stored. Human request/event views
insert --- NEW EPOCH --- on consecutive displayed boot/epoch changes, and label
the first visible epoch even after --limit/filters. Ordering is not regrouped.
--epoch accepts a full recorded 48-hex epoch. Legacy missing IDs are null/UNKNOWN;
a proven legacy execution join uses correlated_epoch_id, never fabricates a
raw epoch_id. New v2 request anchors must match the recorded epoch and digest.
Basic separators do not depend on lifecycle events. Lifecycle audit is separate.

History is bounded, unprivileged and not an authority or live broker query.
No historical success/failure is rewritten on restart. Journald delivery and
retention remain best effort, not a new durability guarantee.
