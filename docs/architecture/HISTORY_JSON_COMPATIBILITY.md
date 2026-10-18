# Intentional history JSON schema2

> Epoch extension (`0.4.1-10~status4`): see [../security/BROKER_EPOCH.md](../security/BROKER_EPOCH.md),
> [../security/RESTART_INVALIDATION.md](../security/RESTART_INVALIDATION.md) and
> [../user/UPDATE_PREFLIGHT.md](../user/UPDATE_PREFLIGHT.md). New queued IDs use authenticated
> `rq_v2_` syntax; old `rq_32hex` examples describe legacy IDs only. Native
> audit schema 1, history JSON 2 and ordinary live snapshot schema 1 remain.
> History epoch separators are presentation only, never authorization.

Schema1 mixed operational identities (ex_/event_N) into requests[] and matched/returned counted those identities. Correcting that meaning and adding explicit event counting is an incompatible contract correction: schema_version increments to2, including JSON error envelopes. Consumers must check the version; schema1 compatibility is NOT silently claimed.

Stable request fields retain types/meanings: identity,request_id,boot_id,broker_instance_id,timestamp,requester_uid,status,observed_state,current_state_known=false,result,exit_code,signal,events. Requests are only authoritative rq_/ch_ lifecycle groups. Additive top-level challenge_id/request_digest on each request make binding scope explicit. correlation_incomplete now correctly permits a fully observed genuine challenge-only request (no queue ID is not inherently incomplete); unknown/conflicting outcome still incomplete, not a retention completeness guarantee.

Success envelope: schema_version=2,mode=requests|events,count_unit=requests|events,requests[],events[],returned,matched,scanned_records,ignored_records,scan_truncated,bytes_read,omitted_records,diagnostic_records,limits,historical_only=true,completeness. matched/returned describe precisely the mode/count_unit, after semantic filters and before/after display limit. Default counts actual requests, --events counts deduplicated projected audit records. Raw input count is scanned_records; malformed/untrusted rows ignored_records; diagnostic_records counts parsed rows without authoritative request association (not malformed/ignored). omitted_records counts valid request-associated rows beyond the2000-request grouping bound, never ordinary diagnostics. --events can still expose those rows with an explicit association when no status filter needs an omitted request outcome.

Events[] preserves event,timestamp,boot_id,source_unit and all previous typed nullable fields; adds request_identity,request_broker_instance_id,correlation_incomplete. For root/PAM records raw request_id remains null when absent. Request timeline events retain their old projection, no synthetic propagated capability/ID. Both mode collections exist; the inactive one is empty. Same cursor/projection duplicates collapse, repeated real views remain.

No input/authority schema changed: MAYI_SCHEMA_VERSION=1 in Journald remains unchanged; history output schema is independent. Same fixed journalctl argv, permission/error semantics, numeric/null/ASCII JSON types and deterministic ordering. See HISTORY_SCHEMA.md for complete current reference.
