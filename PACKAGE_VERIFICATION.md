# CLI package verification

Artifact: /home/eugen/projekte/mayi-journald-development/dist/mayi_0.4.1-10~status2_amd64.deb.

Two independent clean Cargo target/output builds from source ce624dc1bcc1eb0f493794c54c38d2e84c104242, existing Mayi/TPA pipeline, Debian11 Rust/Cargo1.95.0/GCC10.2.1/GLIBC2.31, locked offline dependencies, SOURCE_DATE_EPOCH=1792195200. Identical first/rebuild SHA-256af371f6e80b1e7df4366913e7b8ed282a3824c782380cc73fffb50adc055a50f; cmp PASS. Mandatory exact-package ABI/hardening gate before atomic final artifact rename; maxGLIBC2.30. No stale binary reuse or old identity overwritten.

Package control/version/architecture inspected, dpkg version order status2 >status1 PASS. Build script derives identity/filename/stamp from tpa.json (no shell hardcoded package version). Embedded _build_version exactly 0.4.1-10~status2 newline, matching control. Five modified/new Python modules and two shipped CLI design/compat docs match source; all members root:root, no setuid/setgid/pyc, existing dependencies unchanged. Actual installed version/helper outputs verified on all three distros including broker offline.

Evidence: /home/eugen/projekte/mayi-qualification/cli-0.4.1-10-status2, source.tar, builder/build-twice.log/.exit, candidate.deb, reproduced.deb, abi.json/.exit, package-validation.json, package-identity/files, independent-audit-final.json, primary/retry raw qualification. First/rebuild/VM-payload hash invariant PASS. Report-only later commits do not alter packaged code/docs/build inputs.

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
