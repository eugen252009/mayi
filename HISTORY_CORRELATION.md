# Read-only correlation

Authoritative queue key: trusted broker record (boot_id, broker_instance_id, actual MAYI_REQUEST_ID). Synchronous broker records have no queue ID; they use a distinct ch_ challenge identity. Matching IDs from another boot/instance never merge.

Broker-native explicit bridge MAYI_EXECUTION_ID maps a raw executor record by (boot, execution ID) only when exactly one known identity is mapped in the bounded window. No rq_ prefix inference. PAM maps only via exact (boot, broker instance, challenge, digest) obtained from the broker. Multiple candidate identities make the helper/executor event unassociated; no guesses based on times or UIDs. Mapping ambiguity is preserved even when a broker identity falls outside the identity output cap.

Unassociated execution IDs are shown as ex_ identities. Other events are separate scan-local event_ identities. The default table labels unassociated diagnostics by event name; --json exposes the full event projection. Security-relevant rejections are not silently filtered out just because they lack queue IDs (resource limits/omission counts still apply).

--request shows only actual broker request-ID matches and uniquely demonstrated bridges. It cannot find an absent mapping lost to retention, rate limits, the chosen --since window or scan bounds. No privileged protocol was changed to improve history. Lifecycle snapshots are observations, not current state; even records from this boot can describe a dead/restarted broker. No process/boot liveness inference or journal-derived authorization is performed.

Startup/session helper events can be unassociated by design. Actual root execution and broker dispatch are distinguished. This reader reuses existing MAYI_SCHEMA_VERSION=1; its output schema is independently versioned.
