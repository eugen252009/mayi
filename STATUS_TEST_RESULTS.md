# Status qualification

**STATUS GO. Installation: PACKAGE READY — INSTALLATION PENDING.**

Source tests: Rust135 broker/PAM/UI/logger/state +10 privileged executor/logger PASS; Python147 PASS /9 historical installed-console SKIP (32 focused status +47 history +68 existing). cargo fmt --check and cargo clippy --offline --all-targets -- -D warnings PASS. Commands use documented test-only libpam alias RUSTFLAGS and serialized Rust tests; no operator PAM authentication. Source guard for stored command handoff retains actual challenge/operation and now includes explicit notification callback; no security test deleted or weakened to ignore the operation.

Rust tests: empty/expiry-without-mutation, six exclusive counters, shared/chain dependencies, dispatch-not-running, terminal exclusion, synchronous await-consume/running, observation surviving consumed-record cleanup without authority restoration, full128 snapshot with concurrent changes, kernel-role/socket/exact-message checks without invoking PAM, correlated/duplicate/mismatched start frames, bounded nonblocking root notice. Original one-shot/digest/replay/TTL/PAM/terminal/security tests remain PASS.

Installed exact bytes on Debian11/12/13: all14 gates PASS and final exits0. Status-specific tests verify empty, single/multiple pending, approved sync waiting for consume, selective explicit approvals on a shared-dependency chain, observed actual running1 +waiting2 =total3, completed0, no PAM/session/auth/approval from ten repeated pending polls, no requester/claimedUID/descriptor access,128 live pending across16 synthetic requester UIDs, concurrent samples, NDJSON watch disconnect/recovery/new broker epoch, TTY resize/Ctrl-C and unchanged termios/alternate-screen cleanup, pipe human-watch rejection, and status after reinstall.

Independent audit validates46 numeric/exclusive snapshots per platform,552 actual native records per platform, full raw gate maps/status codes/identity/termios and real>=300s expiry. At128 requests11 CLI queries took1.103s Debian11,1.106s Debian12 (per-platform raw status-large-result retains exact measurement). These include Python process/NSS/IPC startup, not a production CPU/RSS SLA. Broker retained-state and sync observation bounds are structural; watch polls1Hz (min0.5s), no unbounded output buffer.

History and all previous native emission/spawn-rejection/PAM worker SIGTERM/SIGKILL/denial/nonzero/signal/owner/replay/restart/log-socket failure/rate limiting/package cycle/real expiry tests repeated. No cancellation protocol exists: watch cancellation only stops viewing; cycles still rejected by existing tests. Physical suspend, power loss, full-disk journal failure and production-scale NSS latency are not newly qualified.

Evidence: /home/eugen/projekte/mayi-qualification/status-0.4.1-10-status1, source tests/*.log in root, debian*/raw/journald-results/, independent-audit.json, check_results.py. Initial compile visibility error (private impl method) is retained as compile-first.log, fixed before artifact build. No final candidate gate failed; earlier journald5/4 failures remain historical evidence in their original directories.


Tested package source: 90a65fd6d8432f5b6c1e297b24dc91bd80a18f1a. Development 0.4.1-10~status1 amd64. First/rebuild SHA-256: 4ce927013fb811ffa21d9540ac007ff5f47cfff1d9f0c8d2fe3f8e6632e3aab4.
