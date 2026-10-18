# Mayi documentation — authority and navigation

The canonical development checkout is **/home/eugen/projekte/mayi/**.
Start with [PROJECT_STATUS](../PROJECT_STATUS.md), then these current references:

| Reference | Owns |
|---|---|
| [Architecture](ARCHITECTURE.md) | Components, roles, privilege and installation boundaries |
| [Security model and lifecycle](SECURITY_MODEL.md) | Request/view/session/claim identities, TTL, PAM, restart and outcome guarantees |
| [IPC protocol](IPC_PROTOCOL.md) | Supported transports/operations/schemas and integration boundaries |
| [Operations](OPERATIONS.md) | CLI, review UI, waiting, audit/history/status/preflight |
| [Development and release](DEVELOPMENT.md) | Source map, metadata, build/test commands, worktrees and central handoff |
| [Qualification](QUALIFICATION.md) | Exact release/evidence identities, tested scope, failures/skips |
| [Limitations](LIMITATIONS.md) | Assumptions, unproven properties and disconnected experiments |

## Authority and disagreements

The immutable qualified source/artifact identity anchors what was tested.
Implemented enforcement plus executable security tests describe actual behavior;
these current documents state intended contracts, not a replacement for enforcement.
If code and an intended contract disagree, investigate as a correctness issue:
do not silently prefer either, weaken tests or infer a new guarantee.
Qualification evidence is scoped; a passing test is not a universal proof.

Current summaries link to detailed package-shipped references where useful:
[history schema](../HISTORY_SCHEMA.md), [status schema](../STATUS_JSON_SCHEMA.md),
[queue counter mapping](../QUEUE_STATE_MAPPING.md), [broker epochs](../BROKER_EPOCH.md),
[restart](../RESTART_INVALIDATION.md), [preflight](../UPDATE_PREFLIGHT.md),
[CLI compatibility](../CLI_COMPATIBILITY.md), [UI usage](../UX_USAGE.md).
These remain at their existing paths because packaging consumes them.
They are supporting details, not separate current release verdicts.

[Historical index](historical/INDEX.md) distinguishes preserved source-era reports,
earlier qualification and research from current contracts. Compatibility pointers
retain former root paths. Old versioned results must not override final0.4.1-11.
Current tests stay in place; no regression was retired with its old design note.
