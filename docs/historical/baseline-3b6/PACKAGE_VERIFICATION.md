# status3 package verification

Artifact:/home/eugen/projekte/mayi-journald-development/dist/mayi_0.4.1-10~status3_amd64.deb

Two independent fresh-target Debian11 builds from e7f2cc3fe62722bc1bf85d0e502ce3ef2d3601e7, locked offline Cargo, established Mayi/TPA pipeline, SOURCE_DATE_EPOCH=1792195200. Both SHA-256c8285db384a46b4f9489c9700c779171a1fc21b2390b0cae1233e08c9bbc8fbd, cmp PASS. Mandatory exact-package ABI/hardening gate before atomic output; maxGLIBC2.30. Rust/Cargo1.95.0/GCC10.2.1/GLIBC2.31, exact TPA4da9418be15d2d5e212e21ff399a33519ca342522633afaed6341705765370a7. No stale binary/old identity overwrite.

dpkg status3 >status2 PASS; control/amd64/dependencies verified; embedded version stamp matches control; all members root:root, no setuid/setgid/pyc. History+CLI module and five shipped history classification/schema/correlation docs match source. First/rebuild/VM payload bytes identical. Rust/privileged code unchanged; history output schema2 intentional, native/status1 unchanged.

Installed matrix and explicit Debian11 watch rerun retained under /home/eugen/projekte/mayi-qualification/history-classification-0.4.1-10-status3. Exact operator before JSON/native/window captures and after JSON/text retained OUTSIDE source/package; no private operator logs shipped. Two initial classification argument-region edit errors and v1-contract/new synthetic-test assertion failures are retained in task tool/log history and history-old-contract-first.log/history-tests-revised.log/classification-first.log, fixed before artifact build; no final history gate failed.

Preservation-final.json: original/staged8/9 full externally pinned manifests PASS, policy/wrappers unchanged, original dirty main/status/index exact previous snapshot match, operator remains status2 with dpkg -V PASS. No host service restart/sign/tag/push/stage/upload/publish/deployment.

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
