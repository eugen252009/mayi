# Request correlation

A queued operation already has an rq_ ID before its PROPOSED event. The broker stores request_id on the existing bounded Request object alongside its challenge/digest/instance. All broker request/view/decision/expiry/dispatch/result events obtain identity from that object, not requester-supplied log metadata. No correlation cache or authorization protocol field was added.

One queued request currently has one challenge; it can have many sequential view events. Current GET_CHALLENGE replaces prior views for that challenge. MAYI_VIEW_ID_HASH distinguishes those views without exposing a raw authorization nonce. Logs preserve this actual cardinality, not one-view-ever assumptions.

Synchronous requests have no queue Request-ID: correlate their challenge/digest/instance instead. Do not invent rq_ IDs or treat identifiers/digests as bearer credentials.

Cross-service boundary: the unchanged executor protocol transports only a 32-hex claim ID. For a queue it is the rq_ suffix; for synchronous execution it is a challenge prefix. The executor cannot safely infer which namespace applies. Its records therefore carry MAYI_EXECUTION_ID, not a fabricated MAYI_REQUEST_ID. Broker dispatch/result records carry both when meaningful. PAM receives the challenge for decision/account checks but not the queue ID; console login has no request challenge yet.

Consequently the simple MAYI_REQUEST_ID query returns the broker's full known queued lifecycle, not every raw helper/executor record. For full cross-service detail join the broker's challenge and execution IDs (journalctl OR matches or separate queries). This explicit limitation is the reason for CONDITIONAL LOGGING GO rather than an unqualified single-field-all-services claim.

Example join, using actual IDs from a trusted broker record:

```sh
journalctl MAYI_REQUEST_ID="$REQUEST_ID" + MAYI_CHALLENGE_ID="$CHALLENGE_ID" + MAYI_EXECUTION_ID="$EXECUTION_ID" -o json-pretty
```

Apply trusted unit/UID/process constraints when interpreting records. No history query restores or revalidates a capability. Old journal records remain available only under Journald retention; broker restart still loses broker state and never replays it from audit history.
