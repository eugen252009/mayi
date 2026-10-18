# Watch mode

mayi-approve status --watch refreshes every1 second; --interval accepts finite0.5..60 only with --watch. Every tick makes a fresh short-lived credential-checked QUEUE_STATUS transaction; no PAM, auth-session/view creation/renewal or capability use. CPU/memory bounded by polling and small fixed responses.

Human mode requires a supported TTY TERM (xterm/screen/tmux/vt/linux). Alternate screen + hidden cursor are restored in finally on Ctrl-C/SIGTERM/SIGHUP; no raw/canonical/echo mode changes. Redraw only changed human canvas, remeasured width each tick, no snapshot-time repaint flicker. Width resize takes effect at next poll. No scrolling output accumulation; SIGKILL cannot run cleanup.

Pipes/dumb terminals: human --watch exits12 without ANSI. Use --watch --json for line-oriented snapshots/errors; flush each line, no animations/control sequences. On disconnect human canvas replaces all counters with UNAVAILABLE/OFFLINE, never zeros/stale data; next tick attempts normal read-only reconnection. Noninteractive one-shot status works without TTY or stdin.

Console connected/authenticated state is not inferred. Snapshot is current broker state, not a durable record or promise of future state. Watch cancellation stops observation only; it cannot cancel requests.
