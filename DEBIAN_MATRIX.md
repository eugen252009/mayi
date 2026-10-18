# Installed CLI status2 Debian matrix

| Platform | Local version/help online/offline | Real argv / approval dispatch | Existing status/history/native/PAM/security | Package lifecycle |
|---|---|---|---|---|
| Debian11 /systemd247.3-7+deb11u8 |PASS after fixture correction|PASS9 cases|PASS|PASS|
| Debian12 /systemd252.39-1~deb12u2 |PASS after fixture correction|PASS9 cases|PASS|PASS|
| Debian13 /systemd257.13-1~deb13u1 |PASS after fixture correction|PASS9 cases|PASS|PASS|

Primary16-gate process:15 PASS +one metadata-fixture FAIL (raw JSON key-order byte comparison), exit1 on each platform. Dedicated corrected metadata-only process:PASS/exit0 on SAME exact bytes. Both sets preserved and independently validated; do not claim the original process exited0. Semantic JSON probes establish varying key order, and actual before/after records are identical. Full runtime functionality is qualified, not inferred from compilation or relabeling failure.

Each primary run collects657 raw native records, live128-request snapshots/watch/broker restart, history and real>=300-second consumption expiry, PAM/SIGTERM/SIGKILL/termios recovery, exact binding and replay/identity checks. Ordinary metadata process needs neither approver group nor TTY, journal access or broker availability. Real child version remains approval-gated and fails normally when broker offline.

Disposable child overlays, historical backing disks read-only; host status1 not installed/restarted by this task. Existing bounded package-manager lock-wait diagnostics retained (stderr/exit/time/process evidence); final primary runs have no captured failed dpkg attempts. Prior package-cycle anomalies remain historical, not excused/deleted.

Two clean Debian11 locked offline builds identical; maxGLIBC2.30 within ceiling2.31; PIE/RELRO/NX/BIND_NOW/needed-library gate PASS. No runtime dependency/crate/library change.


Runtime/package source commit: ce624dc1bcc1eb0f493794c54c38d2e84c104242. Development0.4.1-10~status2 amd64. Package and independent rebuild SHA-256: af371f6e80b1e7df4366913e7b8ed282a3824c782380cc73fffb50adc055a50f.
