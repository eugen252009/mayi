# Filesystem executor status

**Status: DISCONNECTED / INCOMPLETE.** Mayi 0.4.1 does not enable privileged filesystem execution. Structured filesystem operations remain disconnected from the privileged executor and return `EXECUTION_DISABLED`; they are not production functionality.

The direct filesystem core has historical, limited ext4 test evidence, but its qualification is incomplete. Open items include syscall-generated failure coverage, caller-visible cleanup status, stalled-syscall behavior, live LSM-label/device-node coverage, and independent security review. Those experiments do not qualify the broker-to-executor authorization handoff and must not be treated as a supported feature.

Do not connect, enable, or claim production support for filesystem execution as part of ordinary maintenance. The detailed historical reports are retained under [`history/filesystem/`](history/filesystem/):

- [`FILESYSTEM_EXECUTOR_REMEDIATION.md`](history/filesystem/FILESYSTEM_EXECUTOR_REMEDIATION.md) — qualification evidence, limitations, and remaining blockers.
- [`OPENAT2_HARDENING.md`](history/filesystem/OPENAT2_HARDENING.md) — path-resolution and filesystem-admission evidence.
- [`RACE_HARDENING.md`](history/filesystem/RACE_HARDENING.md) — historical race tests and gaps.
