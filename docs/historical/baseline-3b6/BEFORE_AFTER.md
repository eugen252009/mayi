> Archive view: maintainer-local paths have been omitted. Commands containing
> `[local-only path omitted]` are historical records, not runnable instructions.
> Original bytes remain at the commit/path recorded by the documentation checker.

# Before / after

Initial frozen audit evidence is ../ux-0.4.1-11-ui1/audit/, unchanged and hash-pinned. Corrected capture of the SAME stable package is baseline-retry/ there; the first termios-serialization failure remains.

Compact/details first-page lines:
120x40:12/33 →10/30;100x30:12/31 →10/30;80x24:12/25 →10/24;60x20:13/21 →11/20;40x12:12/13 →11/12;30x8:13/15 →8/8.
Every after-page, not just page1, is tested. Async queue notices also fit30x8 without switching the current set.

Busy status now reads:
Approval: 3 waiting
Execution: 2 running
Other: 1; dispatch: 0
6 active requests

Empty status says No pending approvals / No active requests; --details retains full counters.

Before history: three different rows all rq_v2_bbbbbbbbb... PENDING? -.
After: rq:222222222222, rq:111111111111, rq:000000000000, UNKNOWN -/-.
The full IDs are unchanged in JSON and abbreviations are never accepted as authority/lookup tokens. See after/ for exact raw output/matrices, including shell-code disclosure and executor identity.

Version0.4.1-11~ui2; runtime/package-input source574a63dd05c70656e4014b363ae06afa75c1f273 (unsigned intentionally; signing forbidden). SHA25657a1f4d3aea949e7926db7d1e67898a2ec502713314a615171b76257d1ee7e12. Evidence [local-only path omitted]
