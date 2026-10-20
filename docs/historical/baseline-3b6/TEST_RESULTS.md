> Archive view: maintainer-local paths have been omitted. Commands containing
> `[local-only path omitted]` are historical records, not runnable instructions.
> Original bytes remain at the commit/path recorded by the documentation checker.

# Native Journald test results

**CONDITIONAL LOGGING GO**: native functionality is qualified; cross-service RQ-only scope limitation is documented rather than fabricated.

Final ccc index refresh PASS (95 files / 1,314 chunks / zero errors); this is indexing evidence, not a security gate.

Final source tests: **127 broker/PAM/UI/filesystem/logger + 9 executor/logger Rust tests PASS**, **68 Python PASS / 9 pre-existing installed-console SKIP**, formatting PASS, strict all-targets Clippy PASS, diff checks PASS. Rust tests serialize as documented. Host test-only PAM linker alias points to existing libpam.so.0; it is not a packaged dependency or privilege grant. Final unit tests encode audit data without delivering to the operator journal; real delivery is tested in guests.

Codec tests cover separate native fields, optional absence, canonical numeric exit codes, malformed IDs/numbers/names, duplicate fields, controls/newlines/NUL/ESC, oversize values and field count, unavailable/saturated sockets and no retry loop. Broker tests cover queued ID available at proposal time, challenge mapping, sequential replacement views, restart loss, no invented synchronous rq_ ID and no argument projection. Unknown outcome and pre-spawn rejection cannot use a completed-child event.

Exact installed packages tested in Debian 11/12/13 with real PAM, controlling PTYs and actual journalctl -o json. Gates: native lifecycle; spawn failure vs completion; real wrong-PAM/SIGTERM/SIGKILL recovery; dispatch failure; denial/nonzero/signal/two concurrent pending requests; restart/one-shot/digest controls; unavailable journal; actual per-unit rate limiting; remove/reinstall; real >300-second consumption expiry. Native records show _TRANSPORT=journal plus trusted source metadata. Known argument/stdout/stderr and injection markers are absent from native records.

Debian 13's first final package-cycle attempt returned dpkg exit 2 during removal. Concurrent unattended upgrade activity is recorded; the initial harness did not save dpkg's captured stderr, so exact cause is not asserted. A dedicated exact-artifact retry captures failures and waits up to 180 seconds on explicit lock errors (no forced unlock or disabled updates); its complete remove/reinstall/real approval/consumption cycle PASS. Original exit 1/gate FAIL remains retained, not edited to PASS. Independent audit validates the original other nine gates and separate lifecycle retry.

Earlier iterations retained: prototype 1 normal native tests; 2 outcome-label correction; 3 spawn-observation correction but cross-binary unused-helper Clippy failure and an internal-signature source guard failure. Final code moves broker-only logic to the broker and preserves the actual two-argument stored-operation handoff; tests were not weakened. Prototype versioned packages are not overwritten or qualified as the final candidate.

Evidence: [local-only path omitted] (v4/debian*/raw, lifecycle-retry/debian13/raw, installed-audit-final.json, builder/build-v4.log, abi-v4.json); local source-test logs in journald-evidence/. Full-disk after-enqueue faults, long 24-hour queued expiry and real 300-second executor-IPC timeout injection were NOT run; encoding/outcome logic, real request expiry and actual send denial/rate limiting cover the stated scope. No claim of durable/complete auditing.


Tested runtime/package source commit: `08a4d259a6ae7e9a17afecb31ab3cd5b6d9a4724` (unsigned development commit; no release tag). Development package: `0.4.1-10~journald4 amd64`, SHA-256 `cfeb6844af4b50e55ff20003da05ee5a2a686bbdb5bcf793b64e9fa3e6aa2167`.
