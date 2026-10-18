# Package verification

Artifact: /home/eugen/projekte/mayi-journald-development/dist/mayi_0.4.1-10~journald6_amd64.deb.

PASS: package/version/architecture, both ELF ABI scans (max GLIBC_2.30 <=2.31), PIE/RELRO/BIND_NOW/NX, allowed libraries; no libsystemd/new Rust dependency. Correct explicit systemd >=247/journalctl runtime dependency plus existing Python/libpam/libc dependencies. Python source and four installed history documents match source exactly. Package members root:root, no setuid/setgid bits or shipped pyc, existing service identities/sandbox paths preserved. Actual install/start/remove/reinstall and dpkg verification passed on all three guests.

First/rebuild/VM payload hash invariant verified; old journald4 artifact and qualified original/staged 8/9 bundles unchanged. Operator UI4 remains installed, dpkg -V PASS. Preservation-final.json records exact original dirty status/working/index diff comparisons and pinned stage/policy/full bundle checks.

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
