> Archive view: maintainer-local paths have been omitted. Commands containing
> `[local-only path omitted]` are historical records, not runnable instructions.
> Original bytes remain at the commit/path recorded by the documentation checker.

# Mayi 0.4.1-10 source freeze

This signed source revision freezes the status4 runtime semantics for final-version qualification. The only delta from signed 54e6d148922f4c78b6ef5cb976a3203d71c98b77 is the authoritative Debian version and this freeze record; no security policy, broker/executor/PAM/protocol behavior or dependency changes.

The baseline development package remains immutable:
0.4.1-10~status4 amd64, SHA256 6e785530c84cdf19eaac65419aa549f86290003d2e75c2642222218cba6c1d5e.
Its runtime input is ee22b0a278c2c9110d29bfc37bffcff09ec66bee. Later documentation is not a substitute build input for that historical package.

Final-version qualification, including the new package hash and exact signed source commit, is authoritative only in:
[local-only path omitted]
Its FINAL_DECISION.md supersedes the historical status4 FINAL_DECISION.md in this source tree. A source freeze alone is not FINAL GO; all final artifact, platform, concurrency, ABI and offline bundle gates must pass.

Intentional limits: non-atomic preflight/admission race; best-effort journal; no queue/approval/capability recovery; no general exactly-once effects; TTL checked at consumption, not a promise of start-time TTL; root executor/PAM workers may outlive a broker-only restart; missing results require reconciliation. Private provenance-key loss cannot establish an old ID's authenticity; unsafe or interrupted initial key storage fails closed rather than replacing keys or restoring authority. Legacy IDs remain history data and are not retrospectively authenticated. External fixed-length ID consumers must migrate. Custom PAM/MFA/SSSD and physical suspend/resume are not covered by the stock Debian 11/12/13 amd64 matrix; very tiny terminal chrome and preserved-toolchain trust limits remain.

A definitive root completion retains its actual historical outcome after restart. A per-request pre-claim shutdown fence can establish NOT_DISPATCHED; lifecycle inference or a missing queue entry cannot. No automatic replay, request recreation or approval migration.

The operator host remains status3 unless separately authorized. Candidate/final publication and production deployment are prohibited by this task. No release tag, central admission/staging change or publication key operation is part of this freeze. The immutable final bundle, if all gates pass, is input to the separate centralized release workflow.
