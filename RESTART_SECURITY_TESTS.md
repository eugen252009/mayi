# Restart/security qualification — 0.4.1-10~status4

Runtime source: ee22b0a278c2c9110d29bfc37bffcff09ec66bee.
Evidence: /home/eugen/projekte/mayi-qualification/restart-0.4.1-10-status4/.
Read independent-audit-final.json and its exit 0, not just a summary.

## Source gates
* Python: 216 PASS, 9 historical skips (13 new epoch/preflight/CLI/history cases).
* Rust: 143 main + 13 executor PASS; serialized offline tests.
* cargo fmt --check, strict all-target Clippy, compileall, shell syntax: PASS.
* Existing PAM, capability, command binding, consumption expiration, replay,
  queue/DAG, status/watch, history and bounded native logger tests retained.
* 60 shutdown-versus-consumption races prove no request is both claimed and
  emitted as safely invalidated. This is not an exactly-once side-effect claim.
* 256 independent instance generations, 1,024 request nonce/collision checks,
  five authenticated repeated restart simulations; current-epoch unknown IDs,
  old authenticated IDs, forged tags/epochs, malformed IDs and legacy syntax.
* Fixed-key HMAC independent known-answer; canonical map ordering and
  concatenation-boundary cases; persistent key permissions, partial-file and
  symlink rejection. No key bytes included in evidence.

## Installed on Debian 11/12/13
Each original 20-gate run has 19 PASS and one retained FAIL/exit 1.
All three new restart gates PASS: same-epoch approval/execution and independent
Python verification of the installed HMAC; five restarts with stable provenance
key and distinct epochs; exact structured BROKER_EPOCH_CHANGED/exit16; forged,
malformed and legacy IDs; virtual separators/pagination/epoch filtering; clean
pre-claim invalidation versus incomplete execution; old PAM isolation; preflight
permission/offline behavior. A SIGKILL test proves root PID/child survival,
READY on a fresh empty broker while old work runs, UNKNOWN before root result,
and preserved originating epoch and SUCCEEDED/COMPLETED afterward.

The other affected installed gates pass: metadata, nine exact-argv approved CLI
cases, six exclusive live counters/DAG, 128 requests, reconnect/resize/terminal
cleanup, history/events, native lifecycle, spawn/dispatch distinction, real PAM
failure/recovery, denial/failure/signal/concurrency, restart/one-shot,
unavailable/rate-limited Journald, package cycling and real consumption expiry.

## Original failures and separately qualified retries
The original classification fixture expected exactly three requests in an
integer-second journal window. The preceding new PAM gate left one pending
request; its real REQUEST_INVALIDATED record at shutdown landed in that same
window. All platforms returned four real requests: DENIED, DENIED, SUCCEEDED,
and that explicitly fenced old request. The evidence includes full JSON and
tracebacks; no product records were removed or relabeled.

First targeted retry narrowed both request and event views by epoch. It failed:
PAM authentication diagnostics without epoch correctly disappeared under that
filter. Those failures/exit1 remain in classification-retry/.

Second targeted retry narrows request counting by the recorded current epoch,
but keeps unknown-epoch diagnostics in the unfiltered event view.
Same immutable package, all platforms PASS/exit0 in classification-retry2/.
No runtime, package or original evidence was changed for either retry.
Acceptance explicitly joins the original security gates and second retry.
