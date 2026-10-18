# CLI, approval UI, audit and observations

## Local metadata and exact argv

Run mayi --version / mayi-approve --version or --help locally: no broker/PAM/request.
The authoritative version source is package metadata, not host dpkg/environment.
Use mayi -- EXECUTABLE ARG... to force executable dispatch for a reserved name.
After the executable, --help, --version, empty values and metacharacters remain
child arguments; they do not become Mayi options. Unknown leading options fail12.

Examples require separate human approval when they execute anything:
```sh
mayi /usr/bin/printf '%s\n' 'literal; data'
id=$(mayi --queue /usr/bin/true)
mayi --status --json "$id"
mayi --wait --fail=0 "$id"
```
Do not infer success from status-query exit0; inspect job/result/outcome.

## Human approval and waiting

mayi-approve with no arguments starts the per-process PAM-authenticated console.
Use your own interactive TTY; never automate real credentials. Executor UID0/
GID23012 stays visible. Space toggles full escaped details, [/] page, a approves
pending requests in the CURRENT bound set, d denies after selection, q exits
without cancelling requests. Expanded controls expose skip/follow-up and numeric
subsets; individual numeric selection retains indices0..9 limitation.
New-arrival notices do not silently replace the displayed set. Review every
path/argv page before deciding; the UI does not infer effects.
Pending-first presentation preserves original numeric indices and dependency
execution order. Dispatched context is not inferred actual child start.
See [UI details](UX_USAGE.md) and [manual](../../man/mayi-workflow.7).

All six supported sizes120x40,100x30,80x24,60x20,40x12,30x8 were tested. Below30x8
is unproven. Plain/details dumps may use scrollback. Requester animation is bounded
to stderr geometry and absent for redirected/unsupported terminals. No redraw
owns PAM's password input; termios/echo recovery is tested within stated scope.
SIGKILL cannot execute application cleanup, and no universal terminal-recovery
claim follows from catchable-signal tests.

## Native audit and history

[audit.rs](../../executor/src/audit.rs) emits bounded best-effort native Journald.
A missing/dropped/rate-limited record is not evidence that no operation ran.
Reader history is an unprivileged bounded journal projection, never broker IPC,
approval/session recovery or execution. It filters trusted service/UID/transport/
typed fields and never projects raw MESSAGE/argv/output/environment/secrets.
Default rows require genuine broker request binding; --events exposes diagnostics,
including uncorrelated PAM/session/health/executor records without fake requests.

```sh
mayi history --json
mayi history --events --json
mayi history --request FULL_REQUEST_OR_CHALLENGE_ID --json
```
New request aliases use nonce prefixes only for human presentation; use full IDs
for lookup. UNKNOWN means unconfirmed historical outcome, not current pending
work. Epoch separators are virtual. MAYI/EXIT distinguishes broker and child codes.
Unique explicit correlations, not time/UID guesses, join records. View expiry
does not establish request expiry. Scan bounds20000 records/16MiB/20s/2000 groups
and permissions/retention can omit data; omissions are reported.
See [schema](../architecture/HISTORY_SCHEMA.md) and [correlation](../architecture/HISTORY_CORRELATION.md).

## Live status/watch/preflight

```sh
mayi-approve status
mayi-approve status --details --json
mayi-approve status --watch --plain
mayi-approve status --watch --json
mayi-approve status --preflight --json
```
Aggregate status uses the existing approver role, no PAM/session/view/consume.
Compact/details derive from one snapshot; JSON retains full counters. Dispatching
means claimed but start not observed; running means correlated spawn observed,
NOT all OS processes. Retained unknown terminal work is separate.
ANSI watch needs supported TTY; --plain explicitly supports pipes/dumb terminals.
Interval finite0.5..60 seconds with watch; resize/reconnect/epoch changes remain
observations. Errors leave alternate screen before plain-fallback advice.
Ctrl-C stops observing, never cancels jobs.

Preflight READY=0, BUSY=3, UNKNOWN=4; --watch combination rejected12.
READY is not admission fencing, restart authorization, physical-idleness proof or
guarantee about the next instant. A restarted empty broker may coexist with an
old root child. Coordinate admission and reconcile work externally before any
separately authorized maintenance. Read [limitations](../security/LIMITATIONS.md).
