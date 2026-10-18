# History classification status3 installed matrix

| Platform | Request-only/events/JSON/challenge+queue/native | Status/CLI/PAM/security | Package cycle |
|---|---|---|---|
| Debian11 /systemd247.3-7+deb11u8 |PASS|PASS with explicit watch fixture rerun|PASS|
| Debian12 /systemd252.39-1~deb12u2 |PASS|PASS|PASS|
| Debian13 /systemd257.13-1~deb13u1 |PASS|PASS|PASS|

Primary17-gate Debian12/13 exits0; Debian11 initialexit1/live-status-watch assertion failed (other16 PASS). Same package targeted Debian11 watch rerun exits0 with verified direct Python-child SIGINT, full transcript before assertions, resized TTY, unchanged termios and restored screen/cursor. Exact original missing-marker cause cannot be established because the first fixture didn't export that transcript. Both evidence sets retained; no initial failure relabeled. Independent audit validates the explicit exception and actual rerun. See HISTORY_REGRESSION_RESULTS.md.

Each platform classification yields3 actual ch_ requests and26 events (9 unassociated diagnostics), successful9-event root/PAM/broker correlation, request/event limit/status/challenge access checks and no broker counter mutation. Existing queued rq_ flow remains visible; history JSON2 vs status/native schema1 verified. Native totals differ by extra failure/retry diagnostics; raw counts in independent audit, not inferred. Source tests203 Python/9 SKIP,135+10 Rust,format/strictClippy/syntax PASS.

Actual installed package from pinned SHA, disposable child overlays/read-only historical backing disks. No host install/restart. Existing package manager failure capture/strict bounded lock waits retained; final primary cycles have no captured dpkg failures. Prior unrelated package anomalies remain in historical evidence.

Two fresh Debian11 Cargo targets/locked offline builds identical, maxGLIBC2.30 within2.31, PIE/RELRO/NX/BIND_NOW/needed-library gate PASS. Runtime dependencies unchanged; no new library/crate/privileged IPC.


Runtime/package source: e7f2cc3fe62722bc1bf85d0e502ce3ef2d3601e7. Development0.4.1-10~status3 amd64. Package and independent rebuild SHA-256:c8285db384a46b4f9489c9700c779171a1fc21b2390b0cae1233e08c9bbc8fbd.
