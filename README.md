# Mayi

**STABLE — SECURITY MAINTENANCE.** Mayi lets an unprivileged agent or application
request an exact executable and argument vector for explicit human approval and
PAM authentication before root execution. It is not a command-safety analyzer:
the human must assess the program and every argument, especially an interpreter.

**Start with [PROJECT_STATUS.md](PROJECT_STATUS.md) and the [Documentation Index](docs/INDEX.md).**
The index answers **what exists, why it exists, and where its implementation,
tests and evidence live**, including a [Why Does This Exist?](docs/INDEX.md#why-does-this-exist)
table and [component map](docs/INDEX.md#component-map).

## Documentation

| Topic | Description |
|---|---|
| [Documentation Index](docs/INDEX.md) | Complete navigation, rationale and component map |
| [Architecture](docs/architecture/ARCHITECTURE.md) | System design and components |
| [Security Model](docs/security/SECURITY_MODEL.md) | Authorization and trust boundaries |
| [User Guide](docs/user/OPERATIONS.md) | CLI and approval workflows |
| [Development](docs/development/DEVELOPMENT.md) | Building, tests and packaging paths |
| [Qualification](docs/qualification/QUALIFICATION.md) | Verified properties and evidence |
| [Known Limitations](docs/security/LIMITATIONS.md) | Explicitly unsupported guarantees |

## Supported scope

Qualified release **0.4.1-11**, **Debian 11/12/13 amd64**. Canonical development
source: this repository's **main** branch on GitHub. Any checkout location may
be used; no maintainer-specific directory is required. The intended feature set
is complete. Maintenance now focuses primarily on responding to security issues;
there is no planned ongoing feature expansion.

- Exact-command ownership/binding, explicit human/PAM approval and one-shot claims.
- Per-console authenticated sessions, strict consumption-time expiry and epoch invalidation.
- Synchronous/queued requests and dependencies; read-only wait/status/preflight.
- Bounded review UI, native Journald and historical request/diagnostic views.

Filesystem execution is **DISCONNECTED / INCOMPLETE**; other platforms/custom PAM
are unqualified. One-shot authorization is not general exactly-once effects.
See [security](docs/security/SECURITY_MODEL.md) and [limitations](docs/security/LIMITATIONS.md).

## Basic workflow

A requester can submit, for example, `mayi /usr/bin/id`. In a separate human-owned
interactive TTY, `mayi-approve` authenticates and presents the exact operation.
Nothing executes without an explicit accepted decision. `mayi --help` and
`mayi --version` are local metadata commands, not requests.
Read [operations](docs/user/OPERATIONS.md) before privileged use; examples are not
authorization to run them. Never automate real PAM credentials or retry uncertain
side effects automatically.

## Installation and development

Obtain the **exact qualified package** through the authorized release workflow,
verify its provenance/hash, and separately authorize installation/account setup.
This repository's version/status is not proof of current APT availability or
permission to install/restart. [Qualification](docs/qualification/QUALIFICATION.md)
records identities and central signing/admission/publication prerequisites.
[Development/build instructions](docs/development/DEVELOPMENT.md) describe external
dependencies, [fresh-checkout setup](docs/development/DEVELOPMENT.md#fresh-checkout-setup),
source checks and release boundaries; do not rebuild the immutable 0.4.1-11 release.

[AGENTS.md](AGENTS.md) guides coding agents. [Historical index](docs/historical/INDEX.md)
retains earlier investigations without presenting them as current specifications.
Contact [mayi@lupricht.net](mailto:mayi@lupricht.net); report vulnerabilities privately
through [docs/SECURITY.md](docs/SECURITY.md). [MIT license](LICENSE).
