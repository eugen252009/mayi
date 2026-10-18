# STATUS GO

Installation state: **PACKAGE READY — INSTALLATION PENDING**. Development0.4.1-10~status1; runtime/package source90a65fd6d8432f5b6c1e297b24dc91bd80a18f1a. Package SHA and identical rebuild4ce927013fb811ffa21d9540ac007ff5f47cfff1d9f0c8d2fe3f8e6632e3aab4.

| Requested gate | Result |
|---|---|
| Pending approvals |PASS: real1/3/128 and no poll approval/authentication |
| Dependencies |PASS: approved chain/shared prerequisites; exclusive mapping; terminal blocked separate |
| Running |PASS: actual spawn observation, separate dispatching; no pre-spawn RUNNING claim |
| Total active |PASS: distinct requests, sum of six exclusive buckets,46 validated samples/distro |
| Snapshot consistency |PASS: one broker mutex/one monotonic sample, no read mutation/IO under lock |
| IPC authorization |PASS: existing kernel/NSS approver role +approval socket, strict message/FD rejection |
| JSON |PASS: schema1 numeric/bounded/consistent; no invented zeros on failure |
| Watch/restart |PASS: TTY resize/cancel/termios/screen cleanup; NDJSON offline/recovery/new epoch |
| Security regressions |PASS:135+10 Rust,147 Python/9 explicit SKIP,fmt,strictClippy,installed PAM/terminal/TTL/replay/binding |
| Debian11/12/13 |PASS: all14 exact-package installed gates, exit0 each |
| Package/ABI/reproducibility |PASS: two byte-identical fresh Debian11 builds,maxGLIBC2.30,hardening,version order |

Limits are explicit state semantics, not missing mandatory qualification: running is observed spawn with outstanding final RPC, not an instantaneous OS process-tree census. A dropped start notice remains unconfirmed/unknown; unknown outcome or broker restart can leave residual work. Terminal queued blocked/unknown counts are separate, not active. Effective expiry is read-only, not cleanup; non-approved dependency jobs remain pending before approved dependency waiting. No cancellation protocol/console-health tracker is invented. Scope is the current approver's existing global aggregate visibility. Physical suspend/power-loss/full-disk and custom PAM/NSS production latency are not claimed by this stock Debian qualification.

No history-based state reconstruction, capability persistence/recovery/replay, new permission or privileged root endpoint. Necessary opt-in start observation shares unchanged authority/operation/claim semantics; see STATUS_PROTOCOL.md. Mixed old root/new broker fails closed, no automatic retry.

All eleven requested reports are in source root; raw evidence /home/eugen/projekte/mayi-qualification/status-0.4.1-10-status1/, independent-audit.json and check_results.py. Qualified/staged original8/9 bytes and stage/policy, original dirty main checkout/index, and installed operator journald6 verified unchanged. No task signing/tag/push/stage/publish/upload/deploy or host service restart.

## Separate local installation approval required

Not performed by the agent. Keep the human's approval console in its own interactive TTY; never automate the real approver's PAM/password.

```sh
mayi-approve
# Another terminal, only after explicit installation approval:
mayi /usr/bin/systemd-run --unit=mayi-install-status1 --collect --no-block --property=Type=oneshot /usr/bin/dpkg -i /home/eugen/projekte/mayi-journald-development/dist/mayi_0.4.1-10~status1_amd64.deb
```

Transient installer unit avoids stopping its own parent Mayi executor during package replacement. Submission/ambiguous Mayi result is not proof installation completed; do not retry automatically or force an existing unit name. Inspect read-only results:

```sh
dpkg-query -W -f='${Version}\n' mayi
dpkg -V mayi
systemctl is-active mayi-broker mayi-pam-auth mayi-privileged-executor
journalctl -u mayi-install-status1 --no-pager
mayi-approve status --json
```

Status still requires the existing approver role; journal diagnostics require existing reader permissions. No automatic group/ACL change or privilege fallback.

## Verified rollback (also needs explicit approval)

Exact existing journald6 package preserved in dist/rollback/mayi_0.4.1-10~journald6_amd64.deb. SHA-256 7149d79e8aec0f8a7c119a9f8aa0f9ede00f7120cd2674c6b3754d2d8bccb51a. No rebuild, purge or configuration deletion:

```sh
mayi /usr/bin/systemd-run --unit=mayi-rollback-journald6 --collect --no-block --property=Type=oneshot /usr/bin/dpkg -i /home/eugen/projekte/mayi-journald-development/dist/rollback/mayi_0.4.1-10~journald6_amd64.deb
dpkg-query -W -f='${Version}\n' mayi
dpkg -V mayi
systemctl is-active mayi-broker mayi-pam-auth mayi-privileged-executor
journalctl -u mayi-rollback-journald6 --no-pager
```



Tested package source: 90a65fd6d8432f5b6c1e297b24dc91bd80a18f1a. Development 0.4.1-10~status1 amd64. First/rebuild SHA-256: 4ce927013fb811ffa21d9540ac007ff5f47cfff1d9f0c8d2fe3f8e6632e3aab4.
