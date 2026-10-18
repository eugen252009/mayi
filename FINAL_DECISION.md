# CLI GO

Installation state: **PACKAGE READY — INSTALLATION PENDING**.

Development0.4.1-10~status2; runtime/package source ce624dc1bcc1eb0f493794c54c38d2e84c104242. First/rebuild SHA-256af371f6e80b1e7df4366913e7b8ed282a3824c782380cc73fffb50adc055a50f, byte-identical, maxGLIBC2.30. Package under source dist/.

Root cause: missing metadata handlers fell through to trusted executable resolution; stale component __version__ was not Debian identity. Fixed existing dispatcher with shared local metadata +embedded build stamp from tpa.json. -- separator first; child argv untouched; unknown leading flags usage12. Bare version deliberately remains an executable name; use --version/-V. No broker/PAM/security semantics changed.

Version output: mayi 0.4.1-10~status2 /mayi-approve 0.4.1-10~status2. Local concise help supports actual commands; offline metadata succeeds without queue, native audit or authentication. Nine real argv/approval cases per Debian11/12/13 PASS. 185 Python PASS/9 explicit historical SKIP,135+10 Rust PASS,format/strictClippy/Python+shell syntax PASS. Existing live status/history/Journald/PAM/terminal/one-shot/expiry/binding/replay/access/package cycling all passed.

Initial primary16-gate runs had15 PASS +one metadata-fixture FAIL; raw journal JSON object key order varied. Dedicated corrected test on SAME package compares complete decoded records/fields and passes with raw before/after/order probes. Both initial failures and retry success preserved; independent audit explicitly validates combined evidence rather than rewriting initial exit1. This is a test serialization-comparison error, not a product/security qualification gap.

Limits/compatibility: no bare version alias; explicit -- for option/internal-name executables; sole metadata flags reject trailing input; source version needs its own tpa.json while installed version needs its own stamp (invalid/unavailable ->15). Inherited history bounds/status observation uncertainty/UI tiny-terminal limits unchanged. No new persistence/recovery/platform/MFA claims.

All seven requested CLI reports are in the workspace; raw evidence /home/eugen/projekte/mayi-qualification/cli-0.4.1-10-status2/. Exact qualified original/staged8/9 bundles, policy/wrappers, dirty original main/index and installed operator status1 verified unchanged. No host install/restart, sign/tag/stage/push/upload/publish/deploy.

## Installation (separate approval; NOT performed)

Human keeps mayi-approve in their own interactive TTY and performs any PAM authentication themselves. In another terminal, only after explicit approval:

```sh
mayi-approve
# Separate terminal:
mayi /usr/bin/systemd-run --unit=mayi-install-status2 --collect --no-block --property=Type=oneshot /usr/bin/dpkg -i /home/eugen/projekte/mayi-journald-development/dist/mayi_0.4.1-10~status2_amd64.deb
```

The transient installer avoids stopping its own Mayi executor during replacement. Submission or ambiguous Mayi result is not proof of install completion; do not auto-repeat or bypass a rejection. Read-only verification:

```sh
dpkg-query -W -f='${Version}\n' mayi
dpkg -V mayi
mayi --version
mayi-approve --version
systemctl is-active mayi-broker mayi-pam-auth mayi-privileged-executor
journalctl -u mayi-install-status2 --no-pager
```

## Rollback (also requires approval)

Exact previous installed status1 package preserved in dist/rollback/mayi_0.4.1-10~status1_amd64.deb, SHA-2564ce927013fb811ffa21d9540ac007ff5f47cfff1d9f0c8d2fe3f8e6632e3aab4. No rebuild/purge/config deletion:

```sh
mayi /usr/bin/systemd-run --unit=mayi-rollback-status1 --collect --no-block --property=Type=oneshot /usr/bin/dpkg -i /home/eugen/projekte/mayi-journald-development/dist/rollback/mayi_0.4.1-10~status1_amd64.deb
dpkg-query -W -f='${Version}\n' mayi
dpkg -V mayi
systemctl is-active mayi-broker mayi-pam-auth mayi-privileged-executor
journalctl -u mayi-rollback-status1 --no-pager
```

Status1 predates --version; use dpkg-query when verifying rollback. Journal reads still need existing permissions; no automatic elevation/group/ACL change.



Runtime/package source commit: ce624dc1bcc1eb0f493794c54c38d2e84c104242. Development0.4.1-10~status2 amd64. Package and independent rebuild SHA-256: af371f6e80b1e7df4366913e7b8ed282a3824c782380cc73fffb50adc055a50f.
