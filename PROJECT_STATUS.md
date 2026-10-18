# Mayi — STABLE — ACTIVELY MAINTAINED

Canonical source and documentation: **/home/eugen/projekte/mayi/**.
Current local review branch: **consolidation/single-source-of-truth**, based on
remote main3b6b6127c6af682e3f7894dd1b98bac31a04a2e3. Consolidation is not pushed.
Future branches use the reviewed canonical baseline or a qualified successor.
The old dirty administrative main worktree is preserved, not an alternate authority.

Qualified stable release: **0.4.1-11**,
source **c5477fb19e1b979be980b451b6242e3565c9425a** (unchanged, **unsigned**).
Supported tested runtime: **Debian11/12/13 amd64**.

Enabled: exact-command Python clients, Rust authorization broker and root executor,
human/PAM approval with per-console sessions, requester isolation, one-shot claims,
strict consumption-time TTL, epoch invalidation, native Journald, request history,
live approval status and read-only update preflight. Structured filesystem
execution is **DISCONNECTED / INCOMPLETE**; other platforms/custom PAM are unqualified.

Exact final qualification:44/44 installed gates and separate3/3 package/CLI
supplement per platform;242 Python +159 Rust passes,9 documented historical skips;
60 races/480 attempts/60 consumptions/zero duplicates; real PAM/terminal/restart,
reproducibility and ABI/hardening evidence. This is scoped testing, not “fully secure”.
[Qualification identities and evidence](docs/QUALIFICATION.md) retain failures,
corrected retries, original records and exact hashes.

Release bundle: **~/projekte/releases/mayi/0.4.1-11/**.
No changes to it or new package builds. Central workflow separately owns source
attestation, release-tag/artifact/APT signing, admission/staging and publication.
Ancestor signature verification does not sign the unsigned final commit.
Source consolidation is not installation/deployment or publication authorization.

Current requirements are satisfied and Mayi is actively used. Justified security,
correctness, compatibility, usability, measured performance and new-functionality
work remains open. The release is immutable; the project is not shut down.

[Documentation index](docs/INDEX.md) • [Architecture](docs/ARCHITECTURE.md) •
[Security](docs/SECURITY_MODEL.md) • [Operations](docs/OPERATIONS.md) •
[Development](docs/DEVELOPMENT.md) • [Limitations](docs/LIMITATIONS.md)
