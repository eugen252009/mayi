# History JSON schema2

> Epoch extension (`0.4.1-10~status4`): see [BROKER_EPOCH.md](BROKER_EPOCH.md),
> [RESTART_INVALIDATION.md](RESTART_INVALIDATION.md) and
> [UPDATE_PREFLIGHT.md](UPDATE_PREFLIGHT.md). New queued IDs use authenticated
> `rq_v2_` syntax; old `rq_32hex` examples describe legacy IDs only. Native
> audit schema 1, history JSON 2 and ordinary live snapshot schema 1 remain.
> History epoch separators are presentation only, never authorization.

See HISTORY_JSON_COMPATIBILITY.md for explicit v1-to-v2 migration. --json emits exactly one object, no ANSI/human text; schema_version=2 for success/error.

Success keys: mode (requests|events),count_unit (same),requests[],events[],returned,matched,scanned_records,ignored_records,scan_truncated,bytes_read,omitted_records,diagnostic_records,limits {records:20000,bytes:16777216,identities:2000,seconds:20},historical_only=true,completeness. Default matched/returned count authoritative request groups in the scanned window; --events counts deduplicated projected audit records. Limits apply after filters to the appropriate rows. Unrelated diagnostics do not use request limit/group capacity. Requests newest-first; events chronological, selecting latest N before display.

Request keys: identity (actual rq_32 or authoritative ch_48),request_id (rq_ or null),challenge_id,request_digest,boot_id,broker_instance_id,timestamp (last trusted realtime local ISO8601 microseconds),requester_uid (integer/null),status,observed_state,current_state_known=false,correlation_incomplete,result (Mayi integer/null),exit_code (normal observed child integer/null),signal (integer/null),events. Group boundaries include boot/instance/identity/challenge/digest. Request success requires authoritative execution finish; PAM/consume alone cannot establish it. Nonterminal history is UNKNOWN with a last observation, not current activity.

Event projection: event,timestamp,boot_id,source_unit,request_id,broker_instance_id,challenge_id,request_digest,execution_id,state,requester_uid,approver_uid,result,exit_code,signal (nullable). Diagnostic collection adds request_identity,request_broker_instance_id,correlation_incomplete; no fake event_N identity and no fabricated raw request_id. Request timelines include uniquely mapped broker/PAM/executor events. Both arrays always exist; inactive mode's array empty.

--request accepts only full rq_32 or ch_48, across namespace/binding scopes kept separate. --events --status filters only request-associated events by that group's outcome. Incomplete/unassociated rows remain accessible without a status/request filter. JSON numeric values are integers/null, never Some(0). No raw MESSAGE/argv/environment/output/reason/session/view/capability data.

Errors: {schema_version:2,error:{code:string,message:string}}, exit12 usage/timestamp,13 journal denial/partial access,15 unavailable/read/timeout,130 interrupt. Help exits0. Successful empty or explicitly bounded history exits0; omissions/truncation counted, never silently current. Diagnostic classification is not malformed-input rejection.

Resource/retention bounds still apply. --request can miss older records outside a newer full scan cap; direct targeted journalctl/explicit bridges are needed for larger exports. Source native audit schema1 and live status JSONschema1 are unchanged.
