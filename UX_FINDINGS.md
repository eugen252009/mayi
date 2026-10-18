# Initial ranked findings (before implementation)

| ID | Severity | Actual issue | Minimal correction / acceptance |
|---|---|---|---|
| A1 | HIGH | Approval chrome/page-height overflow,30x8 clamp | Account entire wrapped screen; all six sizes/all pages fit with visible controls; details lossless. |
| A2 | MEDIUM | Executor identity only in details | Always-visible UID0/GID23012, accurate and no authority change. |
| A3 | MEDIUM | Nonactionable dependency context ahead of pending action | Pending-first renderer only; retain original index/request mapping and every context row. |
| S1 | MEDIUM | Verbose routine status/short watch | Compact default, --details, unchanged JSON and visible unknown/blocked counts. |
| H1 | MEDIUM | Same-epoch rq_v2 labels identical | Human nonce-based abbreviation, full IDs unchanged and no abbreviated lookup. |
| T1 | MEDIUM | Long requester spinner wraps repeatedly | Actual stderr-width bound; same timer/safe ANSI restrictions. |
| W1/E1 | LOW | Unsupported watch lacks plain human path | Explicit --plain; guard unchanged otherwise; JSON pipeline retained. |
| H2 | LOW | PENDING? and RESULT ambiguous | Clear historical UNKNOWN and Mayi/child labels; JSON untouched. |
| E2 | LOW | Raw broker exception lacks safe next step | Static guidance, stable codes, no automatic retry/restart. |

INFORMATIONAL: conservative shell/wrapper previews, escaped complete details, PAM echo-off, cancellation recovery, immutable component binding, native diagnostics/history separation and local metadata are working abstractions to retain. Request origin application name is unavailable; do not invent it or extend privileged protocol merely for UX. No authority, lifetime, execution-order or restart-semantic changes are justified.
