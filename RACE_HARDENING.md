# Race qualification status — superseded

This document records the earlier fake-root implementation and tests. The adversarial audit subsequently reproduced stale FilePatch overwrite, changed-content FileDelete/FileMove, temp pathname substitution, parent-directory movement outside the fake root, commit after expiry, restart replay, special-file blocking, and FD leaks.

Protocol 5 now places proposals in a Rust-owned approval lifecycle; even an approved request can only be internally consumed as `EXECUTION_DISABLED`. The old single-socket path is disabled. Regression tests verify proposal/authorization behavior and that fixture files remain unchanged. This is **not** a proof that the dormant filesystem implementation is race-safe. Do not reconnect it or describe fake-root mutation as qualified.

No hostile-writer commit contract has yet been established. The old code's `openat2` lookup constraints do not protect a commit pathname from replacement and do not ensure a retained directory FD remains beneath the root after a rename.
