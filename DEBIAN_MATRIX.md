# Installed Debian qualification

| Environment | Journald/native queries | PAM + terminal recovery | Execution/denial/signal/restart/expiry | Remove/reinstall |
|---|---|---|---|---|
| Debian 11 / systemd 247.3-7+deb11u8 | PASS | PASS | PASS | PASS |
| Debian 12 / systemd 252.39-1~deb12u2 | PASS | PASS | PASS | PASS |
| Debian 13 / systemd 257.13-1~deb13u1 | PASS | PASS | PASS | PASS after documented dedicated retry |

This is actual installed package execution in disposable systemd VMs, not inferred from a build. No host installation. Original Debian 13 final attempt's package-cycle FAIL is preserved; other nine gates passed. Separate exact-byte lifecycle retry PASS (see TEST_RESULTS.md), with no forced package-manager flags or disabled updates.

All platforms verify native _TRANSPORT=journal, UID/unit/PID/time metadata, queued broker correlation, three distinct views, numeric result/exit fields, absent optional fields, actual signal 15, separate pre-spawn failure, dropped records under tightened rate limits (3 of 80 views received), unavailable broker socket logging with explicit approval still required, and subsequent recovery. No journald access ACL/capability/sandbox weakening was needed: failure fixtures only strengthen the disposable broker's InaccessiblePaths or tighten log rate limits.

Build: fresh Debian 11 Cargo release target, locked offline inputs, Rust/Cargo 1.95.0, existing exact TPA tool/build-deb.sh, SOURCE_DATE_EPOCH=1792195200. ABI checker enumerates both ELF files; max required GLIBC_2.30, within declared >=2.31. PIE/RELRO/NX/needed-library gate PASS. No libsystemd or newer daemon dependency added. Package controls retain established runtime dependencies; no new Rust dependencies. One build of this candidate is recorded; no new bit-reproducibility claim is inferred.

Recorded files: candidate in dist/, exact source-v4.tar and source commit, builder/environment.txt/build-v4.log/.exit and abi-v4.json in the qualification directory. Earlier candidate packages/failed attempts remain distinct. No staging or publication.


Tested runtime/package source commit: `08a4d259a6ae7e9a17afecb31ab3cd5b6d9a4724` (unsigned development commit; no release tag). Development package: `0.4.1-10~journald4 amd64`, SHA-256 `cfeb6844af4b50e55ff20003da05ee5a2a686bbdb5bcf793b64e9fa3e6aa2167`.
