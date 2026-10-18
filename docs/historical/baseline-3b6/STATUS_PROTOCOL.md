# Narrow read-only protocol

> Epoch extension (`0.4.1-10~status4`): see [BROKER_EPOCH.md](BROKER_EPOCH.md),
> [RESTART_INVALIDATION.md](RESTART_INVALIDATION.md) and
> [UPDATE_PREFLIGHT.md](UPDATE_PREFLIGHT.md). New queued IDs use authenticated
> `rq_v2_` syntax; old `rq_32hex` examples describe legacy IDs only. Native
> audit schema 1, history JSON 2 and ordinary live snapshot schema 1 remain.
> History epoch separators are presentation only, never authorization.

Existing /run/mayi/approval/broker.sock, four-byte big-endian UTF-8 JSON frame, protocol5. Request exactly {"type":"QUEUE_STATUS","protocol":5}. Existing approver socket 0660/group23013, parent restricted directory, plus SO_PEERCRED/NSS checks; no claimed UID accepted. Request socket use, wrong role, SCM_RIGHTS or extra keys/protocol are rejected. No PAM required, consistent with existing read-only LIST_PENDING visibility.

Response: ok=true,protocol=5,response_to=QUEUE_STATUS,schema_version=1,broker=ONLINE,broker_instance_id (48 hex),snapshot_unix_ms,scope=approver_global_aggregate; six counters and total_active, blocked_terminal, outcome_unknown_terminal. No payload/authorization secrets. Errors use existing error envelope plus response_to. No successful/denied poll audit emission; NSS lookup failures retain existing bounded role diagnostic. Snapshot response is copied under the broker mutex; writes occur outside it.

Necessary opt-in execution observation: EXEC_REQUEST_OBSERVE has the same exact fields as EXEC_REQUEST (protocol1, request_id, executable, argv) and the same trusted broker UID/strict executable/argv validation/durable one-shot claim before spawn. Only after actual spawn it may send {type:EXEC_STARTED,protocol:1,request_id:32hex}, followed by the unchanged final EXEC_RESPONSE. Root notification uses one MSG_DONTWAIT|MSG_NOSIGNAL send, no retries, no child-control effect. Broker validates strict start keys/protocol/correlation; duplicate/invalid frames fail to existing UNKNOWN and never replay. Final-result validation is unchanged; the same absolute300s deadline covers both frames.

Legacy request type receives final response only. New broker against an old root helper fails closed, never retries without the observation variant. Package units must be upgraded together through normal packaging. Observation metadata cannot be supplied by an ordinary requester; root connection credentials remain checked. It never changes approval, exact bound operation, consume ordering, grants or response result.

Python status client reuses existing framed/credential-checked authority transport, two-second timeout and strict response validation. Counts are integers (not booleans), exclusive sum matches, total+reported terminal counts <=136. Invalid/old broker responses are UNAVAILABLE, not zeros.
