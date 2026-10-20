# Mayi — STABLE — SECURITY MAINTENANCE

Canonical source and documentation: this repository.
Authoritative development branch: **main**, synchronized with GitHub's default
main at git@github.com:eugen252009/mayi.git. Source, current documentation and
manpages are available together on main, not exclusively on a review branch.
The repository uses independent Git storage; no external worktree is required.
Future branches start from main or a qualified successor. The older shared Git
repository and its worktrees remain preserved historical/unfinished work, not a
storage dependency or an alternate development authority.

Qualified stable release: **0.4.1-11**,
source **c5477fb19e1b979be980b451b6242e3565c9425a** (unchanged, **unsigned**).
Supported tested runtime: **Debian 11/12/13 amd64**.

Enabled: exact-command Python clients, Rust authorization broker and root executor,
human/PAM approval with per-console sessions, requester isolation, one-shot claims,
strict consumption-time TTL, epoch invalidation, native Journald, request history,
live approval status and read-only update preflight. Structured filesystem
execution is **DISCONNECTED / INCOMPLETE**; other platforms/custom PAM are unqualified.

Exact final qualification: 44/44 installed gates and separate 3/3 package/CLI
supplement per platform;242 Python +159 Rust passes, 9 documented historical skips;
60 races/480 attempts/60 consumptions/zero duplicates; real PAM/terminal/restart,
reproducibility and ABI/hardening evidence. This is scoped testing, not “fully secure”.
[Qualification identities and evidence](docs/qualification/QUALIFICATION.md) retain failures,
corrected retries, original records and exact hashes.

The qualified release bundle is not included in this source repository.
Its recorded identities are listed in the qualification document above;
no public bundle download is established here. It remains immutable and is not rebuilt/replaced. Disposable development-package
validation of [documentation paths](docs/development/ROOT_DOCUMENTATION_MAP.md) is
not a new qualified release. Central workflow separately owns source
attestation, release-tag/artifact/APT signing, admission/staging and publication.
Ancestor signature verification does not sign the unsigned final commit.
Source consolidation is not installation/deployment or publication authorization.

Current requirements are satisfied and Mayi is actively used. The intended
feature set is complete; maintenance focuses primarily on reactive security fixes.
Ongoing feature expansion is not planned. Any broader change requires a separate,
explicit decision and appropriate qualification. This is a maintenance policy,
not a claim that no vulnerabilities remain or a promise to reject every future
non-security fix. The qualified release stays immutable; fixes need a new identity.

[Documentation index](docs/INDEX.md) • [Architecture](docs/architecture/ARCHITECTURE.md) •
[Security](docs/security/SECURITY_MODEL.md) • [Operations](docs/user/OPERATIONS.md) •
[Development](docs/development/DEVELOPMENT.md) • [Limitations](docs/security/LIMITATIONS.md)
