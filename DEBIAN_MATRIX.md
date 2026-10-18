# Debian restart qualification matrix

Candidate: 0.4.1-10~status4 amd64, runtime ee22b0a278c2c9110d29bfc37bffcff09ec66bee.
SHA256: 6e785530c84cdf19eaac65419aa549f86290003d2e75c2642222218cba6c1d5e.

| Platform | Primary process | Primary gates | Separate classification retry2 |
|---|---|---|---|
| Debian 11 | exit 1 retained | 19 PASS / 1 fixture FAIL | PASS / exit 0 |
| Debian 12 | exit 1 retained | 19 PASS / 1 fixture FAIL | PASS / exit 0 |
| Debian 13 | exit 1 retained | 19 PASS / 1 fixture FAIL | PASS / exit 0 |

All new epoch/HMAC/error/history/preflight/crash/PAM gates passed in the primary
runs. The failure and first failed retry are explained in RESTART_SECURITY_TESTS.
Do not describe any primary run or first retry as exit0.

Debian 11 clean build and independent clean rebuild are byte-identical.
Rust/Cargo 1.95.0; GCC10; glibc 2.31-13+deb11u14; max imported GLIBC_2.30.
Native binaries pass the mandatory ABI/hardening/dependency gate.
Installed package cycling, real PAM, native Journald, strict expiry, one-shot,
128-request live status/watch and command-bound execution passed on all three.
All operations ran in task-owned disposable QEMU guests, not on the operator host.

Evidence paths: restart-0.4.1-10-status4/debian{11,12,13}/raw/,
classification-retry/ and classification-retry2/. The independent acceptance
script requires original failures and retry2 separately. No outcome is inferred
from missing logs or an overwritten result.
