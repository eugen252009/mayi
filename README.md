# Mayi

**STABLE — ACTIVELY MAINTAINED.** Mayi lets an unprivileged requester propose an
exact executable/argv for explicit human approval and PAM authentication before
privileged execution. Submission, authentication, approval, consumption and actual
execution are distinct events. Mayi is not a command-safety analyzer.

**Start at [PROJECT_STATUS.md](PROJECT_STATUS.md)** for the current0.4.1-11 baseline,
supported scope and release identity. **[docs/INDEX.md](docs/INDEX.md)** owns current
documentation navigation and the authority hierarchy.

Canonical checkout: **/home/eugen/projekte/mayi/**.
Python lives in [mayi/](mayi/); the Rust broker/PAM/UI/executor in
[executor/src/](executor/src/); packaging in [executor/package/](executor/package/).
[Development/build/tests](docs/DEVELOPMENT.md), [security/lifecycle](docs/SECURITY_MODEL.md),
[operations](docs/OPERATIONS.md), [qualification](docs/QUALIFICATION.md) and
[limitations](docs/LIMITATIONS.md) are current references.

Root legacy reports are compatibility pointers or explicitly scoped supporting
package references, not alternative current release decisions. [Historical index](docs/historical/INDEX.md)
preserves originals and maps earlier worktrees. No current tests are archived.
No new package, feature, installation, signing, push or publication is implied.

Bugs, security concerns, demonstrated workflow/compatibility/performance problems
and justified new capabilities remain welcome. There is no immediate feature
backlog requirement and no permanent feature freeze. See [agent guidance](AGENTS.md).

Contact [mayi@lupricht.net](mailto:mayi@lupricht.net); report vulnerabilities privately
via [SECURITY.md](SECURITY.md). [MIT license](LICENSE).
