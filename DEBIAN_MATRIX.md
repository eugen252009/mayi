# Installed package matrix — journald6

| Platform | systemd | Exact install/native/history/permissions/restart | PAM, identity, one-shot, expiry | Remove/reinstall |
|---|---|---|---|---|
| Debian 11 | 247.3-7+deb11u8 | PASS | PASS | PASS |
| Debian 12 | 252.39-1~deb12u2 | PASS | PASS | PASS |
| Debian 13 | 257.13-1~deb13u1 | PASS | PASS | PASS |

Eleven gates each, final exit 0 each, 248 raw native records each; independent audit PASS. Actual root and ordinary synthetic requester CLI invocations, real PTYs/PAM and journalctl records, not build-only inference. UID-split scope regression reproduced and corrected on all three. No journal group membership or security sandbox weakening needed.

Earlier journald4 Debian 13 package-cycle exit 2 had missing stderr; that cause remains historically unproven. This task captures every failed dpkg command's stderr/exit/time and package-manager process snapshot. Only explicit exit-2 lock errors receive a <=180-second cooperative wait; never force/unlock/kill package managers or disable security updates. Final journald6 Debian 11/13 cycles had no failed dpkg attempts. Debian 12 removal encountered 52 captured exit-2 attempts over 54.46 seconds: stderr identifies frontend-lock PID 1492 and process snapshots identify /usr/bin/unattended-upgrade. The bounded cooperative retry then completed the unchanged full cycle. All 52 attempts remain FAILED evidence, independently classified as package-manager contention; only the completed cycle is PASS. No lock was removed, package manager killed or security update disabled.

Fresh child overlays of historical Debian qualification bases; boot-provisioned synthetic fixtures only. Operator host not installed/restarted. Current final evidence under /home/eugen/projekte/mayi-qualification/history-0.4.1-10-journald6; initial failing history5 evidence retained separately. Both ELF max GLIBC_2.30, within Debian 11 >=2.31; systemd native/query compatibility confirmed through 257.


Package runtime/source commit: c511c7f948e4b811baec9e83976fec6ec5b898ba. Version: 0.4.1-10~journald6 amd64. Package and independent rebuild SHA-256: 7149d79e8aec0f8a7c119a9f8aa0f9ede00f7120cd2674c6b3754d2d8bccb51a.
