# PACKAGE READY — INSTALLATION PENDING

Current development version: 0.4.1-10~journald6. Runtime/package source commit c511c7f948e4b811baec9e83976fec6ec5b898ba. Earlier journald5 had a genuine journal partition selection bug and remains unqualified; corrected version6 was built twice and independently qualified. No old identity overwritten.

History implementation, default/read-only/native correlation, arguments/status/request/since/JSON, ACL denial, malformed/control/large data and restart behavior PASS. Unknown/incomplete historical records never become current broker state. No privilege expansion, root endpoint, second database, protocol change, capability restoration or replay.

Source: 115 Python PASS /9 historical SKIP; 127+9 Rust PASS; strict Clippy/format PASS. Exact installed Debian 11/12/13: all eleven gates PASS, final exits 0, independent audit PASS. Final package/rebuild bytes identical and max GLIBC_2.30. Root-owned package, no setuid/setgid, correct dependencies, source module/docs verified. Original failed attempts and Debian 13 anomaly history retained/classified, not relabeled.

Known limits: best-effort journal retention/rotation/rate limiting, 20k-record/16MiB/20s/2000-identity window; no unlimited export or production-scale disk latency claim. Older matching records outside the scan require direct targeted journalctl queries; --since alone cannot overcome all older-window omissions. Nonterminal states are last-observed only (question mark; JSON UNKNOWN). Boot/instance scopes remain separate. Correlation requires explicit unique broker bridges; unassociated diagnostics remain separate/incomplete. CANCELED is not fabricated. Access requires existing journal rights; no auto-elevation. Root/compromised emitter is not tamper-proof. Existing UI tiny-terminal limitations remain inherited, not fixed or newly claimed here.

All eleven requested history/package reports are in the source worktree. Qualification: /home/eugen/projekte/mayi-qualification/history-0.4.1-10-journald6/. Raw native JSON, CLI stdout/status, termios records, independent audit and package/rebuild hashes retained.

Qualified 0.4.1-9 and 0.4.1-8 originals/staged copies, stage wrappers, admission policy and original dirty main checkout/index verified unchanged. Operator remains 0.4.1-9~ui4. No host installation/restart, signing, tag, staging, publication/upload, push or deployment. This decision authorizes no such next step.

## Local installation (NOT performed; separate approval required)

Keep the existing approval console in its own interactive TTY. The human, not the agent, performs PAM authentication. In another terminal, after explicit installation approval:

```sh
mayi-approve
# Separate terminal:
mayi /usr/bin/systemd-run --unit=mayi-install-journald6 --collect --no-block --property=Type=oneshot /usr/bin/dpkg -i /home/eugen/projekte/mayi-journald-development/dist/mayi_0.4.1-10~journald6_amd64.deb
```

A transient system unit keeps dpkg outside the services it replaces. Submission is NOT proof installation completed; inspect read-only results before doing anything else:

```sh
dpkg-query -W -f='${Version}\n' mayi
dpkg -V mayi
systemctl is-active mayi-broker mayi-pam-auth mayi-privileged-executor
journalctl -u mayi-install-journald6 --no-pager
mayi history --json
```

Do not automatically repeat an ambiguous Mayi result, force an existing unit name, bypass Mayi rejection, or widen journal permissions. Journal queries still need existing reader permissions.

## Rollback (also requires explicit approval)

Verified exact operator UI4 rollback preserved at dist/rollback/mayi_0.4.1-9~ui4_amd64.deb; SHA-256 5bf2eaa95826a63c4961ae1bc6b0affb6e946119f47466aa89302b2604bfa11a. No rebuild/purge/config deletion:

```sh
mayi /usr/bin/systemd-run --unit=mayi-rollback-ui4 --collect --no-block --property=Type=oneshot /usr/bin/dpkg -i /home/eugen/projekte/mayi-journald-development/dist/rollback/mayi_0.4.1-9~ui4_amd64.deb
dpkg-query -W -f='${Version}\n' mayi
dpkg -V mayi
systemctl is-active mayi-broker mayi-pam-auth mayi-privileged-executor
journalctl -u mayi-rollback-ui4 --no-pager
```



Package runtime/source commit: c511c7f948e4b811baec9e83976fec6ec5b898ba. Version: 0.4.1-10~journald6 amd64. Package and independent rebuild SHA-256: 7149d79e8aec0f8a7c119a9f8aa0f9ede00f7120cd2674c6b3754d2d8bccb51a.
