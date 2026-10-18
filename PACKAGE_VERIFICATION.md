# Status1 package verification

Artifact: /home/eugen/projekte/mayi-journald-development/dist/mayi_0.4.1-10~status1_amd64.deb

Two identical builds: first/second SHA-2564ce927013fb811ffa21d9540ac007ff5f47cfff1d9f0c8d2fe3f8e6632e3aab4; cmp PASS. Source archive from90a65fd6d8432f5b6c1e297b24dc91bd80a18f1a, clean release target per build, locked offline Cargo, SOURCE_DATE_EPOCH=1792195200, established Mayi/TPA pipeline. Debian11 toolchain Rust/Cargo1.95.0,GCC10.2.1,GLIBC2.31; exact TPA SHA4da9418be15d2d5e212e21ff399a33519ca342522633afaed6341705765370a7. Both ELF maxGLIBC2.30 with existing hardening/library ABI gate before final atomic artifact rename. No host/native stale binaries or overwritten prior identities.

dpkg --compare-versions '0.4.1-10~status1' gt '0.4.1-10~journald6' PASS. Package/version/amd64/dependencies inspected; modules and six shipped status design/protocol/schema/security/watch/state-mapping docs exactly source bytes; all members root:root, no setuid/setgid bits or shipped pyc. Final installed services/role tests/actual native emission/status/watch/history and dpkg verification/remove/reinstall PASS on all three distros.

Qualification raw/ABI/build/identity/package member/source/rebuild evidence: /home/eugen/projekte/mayi-qualification/status-0.4.1-10-status1. Reproduced package retained as reproduced.deb there. Four original/staged pinned version8/9 manifests, stage wrappers and policy unchanged; original dirty checkout/status/index exact saved baseline comparison; operator journald6 dpkg -V PASS. No host installation or deployment.

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
