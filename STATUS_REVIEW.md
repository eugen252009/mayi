# Initial status/watch review

S1 MEDIUM: six zero counters and chrome produce roughly15 lines even when empty; long diagnostic labels wrap at30/40 columns. Watch uses alternate screen but draws the same tall canvas, so short terminals overflow. Reproduce audit/status-*.txt and status-empty.txt. Minimal fix compact default with approval/running/other active totals, explicit blocked/unknown outcomes and --details exposing every old label/counter. JSON unchanged. Acceptance empty state immediately says no approvals/no active requests, unknown never hidden, totals match validated snapshot, six-state detail view remains available.

W1 LOW: unsupported human watch is expected when stdout is not a TTY or TERM lacks a recognized ANSI capability. Current guard is security-correct; do not simply broaden it. Improve message and provide explicit --watch --plain append-only human snapshots; retain --watch --json for machine pipes. Acceptance no ANSI on plain/redirected paths; original unsupported usage still fails12 safely; CtrlC/signals restore alternate-screen/cursor/termios; no PAM/session renewal or queue mutation.

Existing unchanged-canvas optimization and fresh reconnect polling are useful. Preserve epoch identity and error UNKNOWN with absent counters, never stale zeros. Presentation grouping must keep dispatch unconfirmed distinct from observed running.
