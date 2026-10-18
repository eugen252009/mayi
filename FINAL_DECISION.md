# HISTORY GO

Installation state:**PACKAGE READY — INSTALLATION PENDING**. Development0.4.1-10~status3; runtime/package e7f2cc3fe62722bc1bf85d0e502ce3ef2d3601e7; package/rebuild SHA-256c8285db384a46b4f9489c9700c779171a1fc21b2390b0cae1233e08c9bbc8fbd.

Root cause: orphan PAM/session/health records were reconstructed into event_N/ex_ pseudo-request groups and consumed request table limits/counters. Fixed authoritative lifecycle classification, preserving genuine nonqueue ch_ requests and existing explicit broker-to-executor/PAM correlations. --events is the separate all-audit projection, never synthetic requests. No broker protocol/security semantics changed.

Actual operator window recaptured24 raw records/10 schema1 identities ->3 requests (DENIED,DENIED,SUCCEEDED0), successful9-event timeline intact; --events24 retains7 standalone diagnostics. Earlier operator reported23/9; deterministic public23-row fixture proves3+6 and captured raw evidence remains unchanged outside package/source.

JSON schema deliberately2: default requests[] only real requests, events[] only diagnostic mode; mode/count_unit make matched/returned units explicit. Native audit1/live status1 unchanged. Full rq_32 or ch_48 detail, status/since/limits, typed privacy/security/resource/access rules verified. Unknown remains genuine incomplete historical outcome, not a filler status for a login event.

Source203 Python PASS/9 explicit SKIP,135+10 Rust PASS, fmt/strictClippy/syntax PASS. Installed Debian12/13 all17 PASS/exit0; Debian11 other16 PASS +initial watch marker assertionFAIL/exit1, with explicit same-package instrumented direct-child SIGINT/watch reconnect/TTY retryPASS/exit0. Independent audit validates exact bytes, initial failure and retry separately; see detailed limits/evidence in HISTORY_REGRESSION_RESULTS.md. No product change or ignored failure to obtain this decision.

Two identical fresh Debian11 builds, maxGLIBC2.30, hardening/dependencies/root ownership/version order PASS. All8 requested reports in worktree; evidence /home/eugen/projekte/mayi-qualification/history-classification-0.4.1-10-status3/. Existing historical releases/staging, dirty main/index, installed status2 preserved.

Remaining limits: retention/rate limiting/rotation and20k/16MiB/20s/2000-request scan/group bounds; records lacking request proof remain diagnostics, missing outcome remains UNKNOWN. Correlation never guesses; older exports may need direct targeted journalctl queries. Schema1 JSON consumers must migrate. Exact initial watch missing-marker cause unproven (first fixture lacked transcript), but real-child signal cleanup is independently exported/verified. No live-state/persistence/recovery or new platform/MFA/process-effect claim.

No host install/restart/sign/tag/push/stage/publish/upload/deploy. No new privileged IPC/database/collector, permission or authorization mutation.

## Local install (separate approval; NOT performed)

Human approver uses their own interactive TTY/PAM; agent never handles real credentials. In another terminal after explicit installation approval:

```sh
mayi-approve
# Separate terminal:
mayi /usr/bin/systemd-run --unit=mayi-install-status3 --collect --no-block --property=Type=oneshot /usr/bin/dpkg -i /home/eugen/projekte/mayi-journald-development/dist/mayi_0.4.1-10~status3_amd64.deb
```

Transient installer avoids stopping its own parent Mayi executor during replacement. Submission/ambiguous result is NOT proof of completion; do not automatically retry/bypass rejection. Verify read-only:

```sh
dpkg-query -W -f='${Version}\n' mayi
dpkg -V mayi
mayi --version
mayi history
mayi history --events --json
mayi-approve status --json
journalctl -u mayi-install-status3 --no-pager
```

History/journal reads and live status retain existing reader/approver permissions; no automatic group/ACL changes.

## Rollback (also requires approval)

Verified exact status2 retained at dist/rollback/mayi_0.4.1-10~status2_amd64.deb, SHA-256af371f6e80b1e7df4366913e7b8ed282a3824c782380cc73fffb50adc055a50f. No rebuild/purge/config deletion:

```sh
mayi /usr/bin/systemd-run --unit=mayi-rollback-status2 --collect --no-block --property=Type=oneshot /usr/bin/dpkg -i /home/eugen/projekte/mayi-journald-development/dist/rollback/mayi_0.4.1-10~status2_amd64.deb
dpkg-query -W -f='${Version}\n' mayi
dpkg -V mayi
mayi --version
systemctl is-active mayi-broker mayi-pam-auth mayi-privileged-executor
journalctl -u mayi-rollback-status2 --no-pager
```

Rollback restores history schema1/mixed diagnostic identities; JSON consumers must check schema version.



Runtime/package source: e7f2cc3fe62722bc1bf85d0e502ce3ef2d3601e7. Development0.4.1-10~status3 amd64. Package and independent rebuild SHA-256:c8285db384a46b4f9489c9700c779171a1fc21b2390b0cae1233e08c9bbc8fbd.
