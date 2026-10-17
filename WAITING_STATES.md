# Waiting states and clocks

Implemented:
- Requester Python CLI: existing status polling, 200ms sleep. Human stderr spinner updates at most four frames/second, only on supported TERM plus a TTY. Monotonic elapsed time begins after submission. No new threads/polls/endpoints. No stdout changes.
- Console decision input: existing one-second poll tick updates an ASCII spinner on supported terminals. Queue snapshots still use the existing read-only protocol. Local elapsed time is not broker health or request age.
- State changes/errors: Python context manager clears active progress; console input guard restores terminal mode on return/error. Decision feedback remains broker-correlated Approved/Denied/Follow-up.
- Unsupported/redirected output: no animation escapes. Existing static pending message remains. Console refuses redirected input/output.
- Expiration: complete broker Unix expiry plus remaining-at-render estimate. This is not a continuously updated deadline. Broker monotonic strict consumption-time expiry remains unchanged. Original authorization lifetime/request creation timestamp are not supplied by LIST_PENDING; none are invented.
- Client input timeout remains 120 seconds, distinct from 310-second decision transport timeout and PAM helper's 300-second timeout.

Examples:
```
/ Waiting for human approval; elapsed 00:18 (not a health check)
- Awaiting decision; elapsed 18s (not broker health)
Waiting for broker decision / PAM authentication; use your own terminal.
No approval is assumed until the broker confirms it.
Approved: 0
Denied: 0
MAYI_REQUEST_EXPIRED
```
An expired authorization needs a fresh request. UI cancellation/quit does not cancel the pending broker request. Broker failures retain existing error reporting; no fake completion is displayed.

Not implemented/claimed: animation during blocking submission, idle-console animation, or a separate reliably observed PAM-in-progress state. During decisions the existing synchronous broker/PAM call owns the terminal; its precise authentication phase is not exposed. Spinner can pause during a blocking socket response. No percentages, health claims, deadline extension, or automatic retry/approval.
