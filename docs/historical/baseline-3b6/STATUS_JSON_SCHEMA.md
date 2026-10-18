# Status JSON schema v1

mayi-approve status --json emits one object. Stable successful keys: schema_version=1,broker="ONLINE",broker_instance_id (48 lowercase hex),scope="approver_global_aggregate",snapshot_unix_ms (broker Unix milliseconds),snapshot_time (UTC ISO8601 milliseconds); numeric pending_approval,waiting_dependency,approved_ready,awaiting_consumption,dispatching,running,total_active,blocked_terminal,outcome_unknown_terminal.

total_active=sum(first six category counters). Additional terminal counts are not active. Max136:128 retained broker records plus8 current synchronous workers whose consumed records may already be normally purged. Real values are observed under one mutex, never reconstructed from audit text. Point-in-time snapshot may become stale immediately; no guarantee that a process remains running. running is observed spawn/awaiting final response, dispatching unconfirmed; unknown outcomes can leave residual work not represented as known running.

Failure object: schema_version=1,broker="OFFLINE" or "UNAVAILABLE",error:{code:integer,message:string}. No counters, timestamps or invented zero. OFFLINE only missing/refused socket; permission/UID/protocol/timeout/other failures UNAVAILABLE. Exit13 access/trusted peer failure,15 query/protocol failure,12 invalid CLI options,130 watch cancellation. Successful query exits0 independent of queue content.

--watch --json emits newline-delimited independent objects, including failure objects during disconnect and fresh ONLINE objects after reconnect/restart; no ANSI/human text. Broker instance identifies restart epochs; failed samples never reuse old counters. Counts/times validated as actual integers, not Some(0)/booleans. Ordering of JSON keys deterministic. Human watch is separate and rejects non-TTY output.

No console health/authentication field because the broker does not track a reliable live console connection. The status client's own successful connection is not a console claim.
