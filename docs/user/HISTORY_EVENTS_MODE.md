# Diagnostic event mode

mayi history --events shows all valid projected native Mayi events in the scanned window, not fake request rows: authorization, PAM, console session, health/start/stop, rejection and uncorrelated executor diagnostics. It uses the SAME scanner/decoder/correlation partition as request mode. No second parser, database, collector, privileged IPC or state recovery.

Default table columns TIME / EVENT / REQUEST-ID. An actual unique request match shows rq_/ch_; otherwise '-'. No event_N/ex_ pseudo-request names. Long names truncate explicitly, output is ASCII escaped/wrapped, no color/ANSI/progress, normal pipe behavior. Events are chronological oldest-to-newest by trusted realtime with deterministic boot/monotonic/source/event/cursor tie breaks. --limit N selects the latest N available event rows and displays them in that order; --all displays all within20k-record/16MiB/20-second scan bounds. Normal request mode remains newest-request-observation first with default20 request rows, up to2000 grouped requests.

--request accepts full rq_v2, legacy rq_32 or ch_48 and selects only demonstrably correlated events. --status filters by derived request outcome before selecting its events; unassociated diagnostics have no request outcome and are excluded by that filter. --since continues to pass a bounded timestamp to fixed journalctl argv. Display limits never alter scan limits or let unrelated PAM events consume request display slots.

--events --json uses schema2 separate events[], requests=[]; normal mode has requests[] and events=[]. Each event preserves existing typed projection plus request_identity/request_broker_instance_id/correlation_incomplete. It NEVER fills a raw executor/PAM request_id merely from a guessed rq_ prefix. Uncorrelated rows retain nullable actual fields. No raw MESSAGE/reason, argv, output, credentials, environment or capability/session/view secret is newly exposed.

Empty/unavailable/access-denied handling remains: successful empty vs explicit13 permission/15 read/12 usage errors. No automatic sudo/group/ACL changes. --events is not a live broker status or capability replay interface.
