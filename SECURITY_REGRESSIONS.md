# History classification security regressions

PASS in the tested scope. Correction confined to Python history reconstruction/projection/rendering and package/docs/version. Existing scanner, fixed executable/vector/native unit+UID filtering, JSON decoder bounds, OS journal permissions and error codes preserved. No broker protocol/source, root/PAM/exec/session/capability/TTL/queue state or audit-emitter schema change. Rust source/Cargo diff is empty.

Authoritative request proof requires typed broker lifecycle plus boot/instance/challenge/digest/stored owner; arbitrary ID prefixes or PAM/session/health state cannot seed requests. Exact unique existing execution/PAM bridges retained; ambiguous/missing mapping never guessed from UID/time. Digest/challenge added to grouping scope, preventing unrelated reused IDs merging. No request success from PAM or consume alone. Incomplete request outcome stays UNKNOWN, historical_only/current_state_known=false.

--events exposes only the SAME typed allowlist, no raw MESSAGE/reason/argv/environment/output, password/API key/session/view/capability secret. Control escaping, field/record/byte/time limits, canonical numbers and duplicate handling remain. Request/event filters operate after proof; scans stay bounded. JSON contract deliberately bumped2; native MAYI_SCHEMA_VERSION1 and live status schema1 unchanged.

203 Python/9 historical SKIP,135+10 Rust, fmt/strictClippy/syntax PASS. Real3-platform classification +permissions/no-broker-mutation, existing one-shot/owner/exact argv/replay/digest/real consumption expiry/PAM worker termination/terminal recovery/native logs/history/status/watch/CLI metadata/package cycle checks qualified. Debian11 watch initial failure +instrumented child-targeted retry are separately retained and validated (see HISTORY_REGRESSION_RESULTS.md); do not claim the primary process exited0.

No journal ACL/group change, auto-sudo, root endpoint/database/collector, capability persistence, recovery/replay, signing/publication or deployment. Filesystem executor remains DISCONNECTED/INCOMPLETE; queue restart persistence/general exactly-once effects remain NOT CLAIMED. Root/compromised emitters are not tamper-proof evidence; existing journal retention/rate-limit and bounded-window limits remain.


Runtime/package source: e7f2cc3fe62722bc1bf85d0e502ce3ef2d3601e7. Development0.4.1-10~status3 amd64. Package and independent rebuild SHA-256:c8285db384a46b4f9489c9700c779171a1fc21b2390b0cae1233e08c9bbc8fbd.
