# Read-only update preflight

mayi-approve status --preflight [--json] reuses the existing approver-only
QUEUE_STATUS snapshot. No new privileged endpoint, authentication session, PAM,
cleanup, view, drain, admission suspension or restart operation is introduced.
--watch with --preflight is rejected (12).

READY (exit 0): this one broker snapshot has no active counters and no retained
outcome_unknown_terminal. BUSY (exit 3): at least one active request, including
pending approvals/dependencies/dispatch/running. UNKNOWN (exit 4): snapshot
unavailable, permission/protocol/transport error, or zero active with retained
unknown terminal outcomes. BUSY takes precedence over a retained unknown count,
which remains visible. JSON retains aggregate snapshot schema 1 and adds
preflight_schema_version=1, preflight, admission_fenced=false,
physical_processes_verified=false. Failure records omit counters rather than
fabricating zeros. Ordinary status exit codes and schema remain unchanged.

READY IS NOT a safe-to-restart grant, atomic idleness, absence of root children,
absence of residual work from earlier epochs, physical process reconciliation,
a deployment action or a guarantee that the next instant is idle. A restarted
broker can report READY while an old executor child still runs. Preflight never
examines or recovers prior authority. Consumers must independently coordinate
admission externally and reconcile outstanding operations.

Status exposes the full existing broker_instance_id in JSON and a compact
human epoch label. Do not equate a transport disconnection with proven restart;
only a changed validated epoch or authenticated stale rq identity establishes
that distinction. Self-upgrades can terminate the response channel.
