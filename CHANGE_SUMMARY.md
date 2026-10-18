# Change summary

> **Later development update:** 0.4.1-9~ui3 adds broker-enforced five-minute sliding authentication sessions; see [AUTHENTICATION_SESSIONS.md](AUTHENTICATION_SESSIONS.md). The ui1 results below are historical and do not qualify this authorization-policy change. ui3 is not packaged or installed; its local tests pass, while installed security qualification remains pending.

Development version: **0.4.1-9~ui1**, branch ui/0.4.1-9-dev in /home/eugen/projekte/mayi-ui-development, based on 5b8f62ba5d2e41d1998aea286674b8285fa44f54. Debian package metadata advances with a prerelease suffix; historical Rust/Python internal versions remain 0.1.0 per existing convention.

Changed: executor/package/tpa.json; executor/src/broker.rs; renderer security regression; mayi/cli.py.
Added: executor/src/approval_ui.rs; executor/src/ui_pty_tests.rs; mayi/progress.py; tests/test_ui_progress.py; these seven reports and local test evidence.

Final decision: **INCONCLUSIVE**.
- Compact display: implemented, unit-tested.
- Expandable details: implemented, paginated, input PTY-tested.
- Command summary safety: conservative preview/warning; escaping tested; not exhaustive wrapper identification.
- Animated waiting: requester and active decision-input wait implemented. PAM/submission/idle animations not implemented.
- Status accuracy: uses existing backend states; no synthetic progress or TTL extensions. Exact PAM phase not exposed.
- Terminal recovery: existing supervisor tests pass; input PTY restoration passes; installed full lifecycle not yet qualified.
- Noninteractive compatibility: schemas/stdout unchanged; tests pass; redirected animation disabled.
- Security regressions: local suites pass; installed PAM and platform qualification remain required.

No Debian package created. Only offline debug/test binaries built locally. No tags, signing, keys, staging, publication, deployment or push. Original dirty developer checkout was not edited; changes are isolated in this worktree. Immutable original/staged 0.4.1-8 manifests are independently rechecked read-only in ui-evidence/release-preservation.log.

Do not deploy this candidate or claim UI GO until missing mandatory tests and documented UX limits are addressed. Previous security qualification is retained as historical evidence, not inherited by this version.
