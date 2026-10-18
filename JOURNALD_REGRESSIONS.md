# Authorization and logging regressions

PASS within original stock Debian qualification scope. No Rust source, broker/PAM/executor protocol, capability/digest/identity/TTL logic, session timer, queue persistence, sandbox, setuid permission or privileged endpoint changed for history. New production code is a Python read-only native projection, fixed-executable subprocess and CLI dispatch. Package adds explicit systemd >=247 dependency because journalctl is required; it is already present on supported installed platforms.

Repeated source tests: 127 broker/PAM/UI/logger/filesystem +9 executor/logger Rust PASS; all existing 68 Python PASS plus 47 history PASS. Nine historical installed-console skips remain skips, not source PASS claims. Installed final artifact repeats actual PAM failure/worker termination/terminal restoration, ownership/digest/replay, one-shot and strict real consumption expiry, explicit deny, root execution normal/nonzero/signal, restart invalidation, logging unavailability and rate limiting. Final history checks show no queue authority/state change on reading.

Native fields, hashes, canonical numeric values and privacy markers remain verified. Logging drop does not authorize; no fallback state recovery or operation retry exists. The filesystem executor remains disconnected/incomplete; no queue persistence across broker restart, no general exactly-once effects, and no execution-start-time TTL guarantee are introduced.

History validates trusted emitting unit/UID/boot metadata, ignores MESSAGE and secrets, rejects malformed fields, and keeps uncertain observations UNKNOWN. No journal membership/ACL elevation: a normal requester receives clear access error 13. Root/compromised emitter assertions are not cryptographic evidence. Existing five-minute auth-session policy trade-off is unchanged.


Package runtime/source commit: c511c7f948e4b811baec9e83976fec6ec5b898ba. Version: 0.4.1-10~journald6 amd64. Package and independent rebuild SHA-256: 7149d79e8aec0f8a7c119a9f8aa0f9ede00f7120cd2674c6b3754d2d8bccb51a.
