# Mayi Documentation Index

## Navigation

- [Getting Started](#getting-started)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [Authentication and PAM](#authentication-and-pam)
- [Requests and Capabilities](#requests-and-capabilities)
- [Broker Restart and Epochs](#broker-restart-and-epochs)
- [CLI and Approval Interface](#cli-and-approval-interface)
- [Journald and History](#journald-and-history)
- [Live Status and Preflight](#live-status-and-preflight)
- [Building and Packaging](#building-and-packaging)
- [Security Qualification](#security-qualification)
- [Why Does This Exist?](#why-does-this-exist)
- [Component Map](#component-map)
- [Design Decisions](#design-decisions)
- [Historical Research](#historical-research)
- [Known Limitations](#known-limitations)
- [Documentation Authority](#documentation-authority)

## Getting Started

Mayi is **STABLE — ACTIVELY MAINTAINED**, with qualified release0.4.1-11.
[PROJECT_STATUS](../PROJECT_STATUS.md) owns the exact status/scope, not a feature
roadmap. [README](../README.md) introduces the purpose and basic workflow;
[operations](user/OPERATIONS.md) explains usage. Canonical repository:
/home/eugen/projekte/mayi/, self-contained Git storage, authoritative **main**.

Suggested reading: status → architecture → security → operations → development.
If diagnosing a subsystem, use the component map or the questions below instead
of searching dozens of release reports. All links are ordinary GitHub Markdown;
no website, JavaScript or external search index is needed.

## Architecture

[Architecture](architecture/ARCHITECTURE.md) explains what runs where and which
component legitimately owns each decision. **Why it exists:** keep unprivileged
request submission, human authentication, broker authorization and root execution
separate; renderer output is not execution input. [IPC](architecture/IPC_PROTOCOL.md)
owns transports, role separation, message families and independent schemas.
Implementation: [broker](../executor/src/broker.rs), [entry/service handling](../executor/src/main.rs),
[client transport](../mayi/executor.py). Checks: [broker security tests](../executor/src/broker_security_tests.rs),
[protocol tests](../tests/test_protocol.py). [D01–D03](decisions/INDEX.md#d01-peer-identity-not-caller-assertions)
index the supported reasoning, not invented alternatives.

## Security Model

[Security model and lifecycle](security/SECURITY_MODEL.md) is the single owning
security overview. **Why it exists:** distinguish actual authority from caller
assertions, display, authentication, observations and physical outcomes.
It defines [binding](security/SECURITY_MODEL.md#binding-and-enforcement) and
[distinct objects](security/SECURITY_MODEL.md#distinct-objects), not a claim of
universal security. Implementation: [broker](../executor/src/broker.rs),
[root executor](../executor/src/bin/mayi-privileged-executor.rs).
Tests: [security](../executor/src/broker_security_tests.rs),
[deadline boundaries](../executor/src/broker_deadline_tests.rs).
[Limitations](security/LIMITATIONS.md) states assumptions and unproven scope.

## Authentication and PAM

[Authentication is not request authorization](security/SECURITY_MODEL.md#authentication-is-not-request-authorization)
explains the separate helper and per-console sliding session. **Why it exists:**
broker-enforced authentication cannot be replaced by a console's claim that PAM
succeeded. Current sessions require process/terminal binding and fresh account
policy, while legacy no-session decisions still authenticate per decision.
A cached decision is NOT a repeated password/MFA authentication.
Source: [PAM helper](../executor/src/pam_auth.rs), [console authentication](../executor/src/console_auth.rs),
[sessions](../executor/src/console_sessions.rs). Tests: [PAM](../executor/src/pam_security_tests.rs),
[sessions](../executor/src/console_session_tests.rs). Original context: [D04](decisions/INDEX.md#d04-pam-enforcement-outside-the-console),
[D05](decisions/INDEX.md#d05-per-process-sliding-console-authentication).

## Requests and Capabilities

[Request/view/session/claim distinctions](security/SECURITY_MODEL.md#distinct-objects)
and [expiration/dependencies](security/SECURITY_MODEL.md#expiration-and-dependencies)
explain what is created, approved, spent or invalidated. **Why it exists:** a
one-shot view is not a consumed capability, an expired view is not an expired
request, and a valid claim does not prove execution began or completed.
[IPC](architecture/IPC_PROTOCOL.md) covers async requests/dependency ownership;
waiting is observation, not authorization or cancellation.
Source: [broker](../executor/src/broker.rs), [operation model](../mayi/operations.py),
[CLI queue/wait](../mayi/cli.py). Tests: [consumption client](../tests/test_consume_client.py),
[deadline regressions](../executor/src/broker_deadline_tests.rs). Reasoning:
[D03](decisions/INDEX.md#d03-one-way-consumption-and-root-claims),
[D06](decisions/INDEX.md#d06-check-expiry-at-the-selected-transition),
[D15](decisions/INDEX.md#d15-asynchronous-requests-and-dependency-waiting).

## Broker Restart and Epochs

[Epoch/restart/outcome contract](security/SECURITY_MODEL.md#epoch-restart-and-conservative-outcome)
and [epoch details](../BROKER_EPOCH.md) explain fresh broker identities, authenticated
rq_v2 provenance and fail-closed stale authority. **Why it exists:** old authority
must not revive, but absence of RAM state alone cannot authenticate an old ID or
prove an operation did not run. [Restart details](../RESTART_INVALIDATION.md) and
[outcome semantics](../EXECUTION_OUTCOME_SEMANTICS.md) preserve that distinction.
Source: [epoch fence](../executor/src/broker_epoch.rs), [IDs](../executor/src/request_ids.rs),
[client IDs](../mayi/request_ids.py), [evidence-only recovery](../mayi/recovery.py).
Tests: [epoch Rust](../executor/src/broker_epoch_tests.rs), [epoch Python](../tests/test_epochs.py).
[Porta guidance](../PORTA_RECOVERY_CONTRACT.md) changes no Porta code and never
licenses automatic replay. See [D07–D09](decisions/INDEX.md#d07-epoch-bound-authenticated-request-identities).

## CLI and Approval Interface

[Operations](user/OPERATIONS.md#local-metadata-and-exact-argv) owns usage and
[human review](user/OPERATIONS.md#human-approval-and-waiting). **Why it exists:**
review the exact bound request while keeping controls/executor visible and
preserving child argv and original selection indices. Paging/new arrivals do
not change approval scope; UI order does not change execution order.
[UI detail](../UX_USAGE.md), [CLI compatibility](../CLI_COMPATIBILITY.md) and
[dispatch design](../CLI_DISPATCH_DESIGN.md) are package-owned detail references.
Source: [CLI](../mayi/cli.py), [metadata](../mayi/cli_metadata.py),
[approval entry](../mayi/approval_cli.py), [renderer](../executor/src/approval_ui.rs),
[waiting](../mayi/progress.py). Tests: [dispatch](../tests/test_cli_dispatch.py),
[PTY input](../executor/src/ui_pty_tests.rs), [presentation](../tests/test_ux_presentation.py),
[waiting](../tests/test_ui_progress.py). Manuals: [mayi(1)](../man/mayi.1),
[workflow(7)](../man/mayi-workflow.7). [D12](decisions/INDEX.md#d12-bounded-review-without-changing-execution-order)
and [D13](decisions/INDEX.md#d13-metadata-dispatch-must-not-reinterpret-child-argv) explain constraints.

## Journald and History

[Audit/history operations](user/OPERATIONS.md#native-audit-and-history) explains
native fields and read-only projection. **Why it exists:** give searchable
correlated observations without granting a history service authorization power.
Unassociated PAM/health/executor events are diagnostics, not invented requests;
UNKNOWN is historical uncertainty, not a live pending row.
Details: [reader design](../HISTORY_DESIGN.md), [schema2](../HISTORY_SCHEMA.md),
[correlation](../HISTORY_CORRELATION.md), [request proof](../HISTORY_CLASSIFICATION.md),
[diagnostic events](../HISTORY_EVENTS_MODE.md), [JSON compatibility](../HISTORY_JSON_COMPATIBILITY.md),
[security boundary](../HISTORY_SECURITY.md).
Source: [native emitter](../executor/src/audit.rs), [history](../mayi/history.py).
Tests: [audit Rust](../executor/src/broker_audit_tests.rs), [history](../tests/test_history.py),
[classification](../tests/test_history_classification.py). Rationale: [D10](decisions/INDEX.md#d10-bounded-native-audit-and-journal-backed-history).

## Live Status and Preflight

[Status/watch/preflight](user/OPERATIONS.md#live-statuswatchpreflight) explains the
read-only snapshot, reconnect/ANSI/plain behavior and READY/BUSY/UNKNOWN.
**Why it exists:** distinguish claimed dispatch from observed child spawn without
turning a query into admission control or authorization cleanup.
Details: [design](../STATUS_DESIGN.md), [protocol](../STATUS_PROTOCOL.md),
[schema1](../STATUS_JSON_SCHEMA.md), [counter mapping](../QUEUE_STATE_MAPPING.md),
[watch](../STATUS_WATCH_MODE.md), [security](../STATUS_SECURITY.md), [preflight](../UPDATE_PREFLIGHT.md).
Source: [snapshot](../executor/src/queue_snapshot.rs), [status client](../mayi/approval_status.py).
Tests: [snapshot](../executor/src/queue_snapshot_tests.rs), [client/watch](../tests/test_approval_status.py).
[D11](decisions/INDEX.md#d11-observe-running-work-without-controlling-admission) records the dispatch/start discovery.

## Building and Packaging

[Development/build/release](development/DEVELOPMENT.md) is the current owning guide;
[package entry](../executor/package/README.md) links it. **Why it exists:** preserve
exact source/package identities, deterministic oldest-supported build inputs,
ABI/hardening gates and separation of publication from deployment.
Source: [product metadata](../executor/package/tpa.json), [version loader](../mayi/version.py),
[builder](../executor/package/build-deb.sh), [ABI checker](../executor/package/verify_abi.py),
[units](../executor/package/usr/lib/systemd/system/), [lifecycle scripts](../executor/package/DEBIAN/),
[Cargo lock](../executor/Cargo.lock). Checks: [ABI regressions](../tests/test_abi_verification.py),
[package identities](../tests/test_package_account_ownership.py).
[Filesystem fixture isolation](development/TEST_ISOLATION.md) governs existing tests,
NOT permission to enable production filesystem execution.
[Documentation checker](development/check_documentation.py) provides reproducible
local link/anchor, historical-identity and index/rationale coverage checks without
a website/search daemon; see the [command](development/DEVELOPMENT.md#local-tests-not-production-qualification).

**Root layout constraint:** 21 root detail Markdown files above are exact inputs
of the unchanged package builder. They remain at those tool-required paths, with
one copy each; this task does not change packaging logic, rebuild11 or replace them
with broken installed links. All obsolete root navigation/report aliases moved
under [historical navigation](historical/navigation-03318f6/INDEX.md). Only README,
PROJECT_STATUS, AGENTS, GitHub-discovered SECURITY policy and those21 tool inputs
remain as root Markdown. Topic guides live here, not as duplicate root specs.

## Security Qualification

[Qualification](qualification/QUALIFICATION.md) owns release identities, evidence
locations, tested properties, skips/failures/retries and signature distinctions.
**Why it exists:** a pass applies to exact bytes and a declared environment, not
a blanket “fully secure” label or an earlier candidate's partial results.
Current11: Debian11/12/13 amd64;242 Python/159 Rust passes,9 documented skips;
44/44 main installed gates plus separate3/3 package/CLI supplement per target;
60 races/480 attempts/60 consumptions/zero duplicates; reproducible package,
ABI/hardening, real PAM/terminal/restart and bundle verification. Existing immutable
raw evidence stays outside source; no huge qualification copy is created.
Code/tests: [security](../executor/src/broker_security_tests.rs), [PAM](../executor/src/pam_security_tests.rs),
[CLI regressions](../tests/test_remediation_gates.py). The unsigned final source
commit is not signed merely because a trusted signed ancestor verifies.

## Why Does This Exist?

The short answers are scoped engineering explanations. Follow each decision link
for constraints, documented alternatives (or their absence), consequences and
supporting source/tests/history. An accepted limitation is NOT invented design history.

| Question | Short answer | Explanation and evidence |
|---|---|---|
| Why not trust requester-supplied identity/approval fields? | Kernel UID/NSS and broker-owned state establish the boundary. | [D01](decisions/INDEX.md#d01-peer-identity-not-caller-assertions) |
| Why store executable/argv instead of executing rendered text? | Review presentation must not become replacement execution input. | [D02](decisions/INDEX.md#d02-stored-exact-operations-not-rendered-commands) |
| Why one-shot capabilities and claims? | Restrict each accepted authorization to one consumption/claim, not exactly-once effects. | [D03](decisions/INDEX.md#d03-one-way-consumption-and-root-claims) |
| Why a separate PAM helper and broker-side gate? | Console-local PAM was bypassable; authenticate the exact account through a constrained authority. | [D04](decisions/INDEX.md#d04-pam-enforcement-outside-the-console) |
| Why bind console sessions to process/terminal? | A successful login is not a UID-wide reusable grant; cached decisions remain explicit and account-checked. | [D05](decisions/INDEX.md#d05-per-process-sliding-console-authentication) |
| Why recheck expiry under the claim lock? | Earlier housekeeping can become stale before the selected security transition. | [D06](decisions/INDEX.md#d06-check-expiry-at-the-selected-transition) |
| Why epoch-bound authenticated IDs? | Authenticate stale provenance without restoring old authority or guessing from missing RAM. | [D07](decisions/INDEX.md#d07-epoch-bound-authenticated-request-identities) |
| Why is the queue not persistent? | Memory-only state is the qualified boundary; a broader historical motivation is not established, and persistence is not permanently rejected. | [D08](decisions/INDEX.md#d08-memory-only-queue-is-the-qualified-boundary) |
| Why conservative execution outcomes/no automatic replay? | Timeout/restart/missing replies do not prove a root operation did not run. | [D09](decisions/INDEX.md#d09-conservative-outcomes-and-no-automatic-replay) |
| Why Journald and bounded history projection? | Reuse searchable typed audit without another privileged history authority; delivery/retention remain best effort. | [D10](decisions/INDEX.md#d10-bounded-native-audit-and-journal-backed-history) |
| Why does preflight not lock admission? | It is a read-only aggregate observation, not a maintenance-control capability or OS census. | [D11](decisions/INDEX.md#d11-observe-running-work-without-controlling-admission) |
| Why paged controls and original UI indices? | Correct demonstrated overflow/action visibility without silently changing request binding or scheduling. | [D12](decisions/INDEX.md#d12-bounded-review-without-changing-execution-order) |
| Why parse only leading metadata and support --? | Local help/version must not reinterpret executable flags or reserve another executable name. | [D13](decisions/INDEX.md#d13-metadata-dispatch-must-not-reinterpret-child-argv) |
| Why is filesystem execution disconnected? | It is outside qualified production scope; source/tests are not enablement. | [D14](decisions/INDEX.md#d14-source-presence-does-not-enable-filesystem-execution) |
| Why can requests wait and depend on other requests? | Async submission separates human approval/dependency readiness from observation; no timing/fairness guarantee is inferred. | [D15](decisions/INDEX.md#d15-asynchronous-requests-and-dependency-waiting) |

## Component Map

| Component | Implementation | Explanation | Purpose / check |
|---|---|---|---|
| Requester CLI and exact argv | [cli.py](../mayi/cli.py), [executor.py](../mayi/executor.py) | [operations](user/OPERATIONS.md) | Propose/observe without ambient grants; [dispatch tests](../tests/test_cli_dispatch.py) |
| Local version/metadata | [version.py](../mayi/version.py), [cli_metadata.py](../mayi/cli_metadata.py) | [development](development/DEVELOPMENT.md#source-and-configuration-authority) | Own build identity, no broker/PAM for help |
| Authorization broker | [broker.rs](../executor/src/broker.rs), [main.rs](../executor/src/main.rs) | [security](security/SECURITY_MODEL.md) | Bind identities/state/claims; [security tests](../executor/src/broker_security_tests.rs) |
| PAM and session transport | [pam_auth.rs](../executor/src/pam_auth.rs), [console_auth.rs](../executor/src/console_auth.rs) | [authentication](security/SECURITY_MODEL.md#authentication-is-not-request-authorization) | Exact-account authentication/account checks; [PAM tests](../executor/src/pam_security_tests.rs) |
| Session lifetime | [console_sessions.rs](../executor/src/console_sessions.rs) | [D05](decisions/INDEX.md#d05-per-process-sliding-console-authentication) | Process/TTY binding; [session tests](../executor/src/console_session_tests.rs) |
| Human UI and waiting | [approval_ui.rs](../executor/src/approval_ui.rs), [progress.py](../mayi/progress.py) | [UI](user/OPERATIONS.md#human-approval-and-waiting) | Review without changing authorization/scheduling; [PTY tests](../executor/src/ui_pty_tests.rs) |
| Root execution | [privileged-executor.rs](../executor/src/bin/mayi-privileged-executor.rs) | [execution boundary](architecture/ARCHITECTURE.md#execution-not-semantic-analysis) | Trusted broker's stored command, durable one-shot claim |
| Request identity and shutdown | [request_ids.rs](../executor/src/request_ids.rs), [broker_epoch.rs](../executor/src/broker_epoch.rs) | [epochs](../BROKER_EPOCH.md) | Provenance/fencing, no authority resurrection; [tests](../executor/src/broker_epoch_tests.rs) |
| Native audit | [audit.rs](../executor/src/audit.rs) | [audit/history](user/OPERATIONS.md#native-audit-and-history) | Bounded best effort; [audit tests](../executor/src/broker_audit_tests.rs) |
| History and recovery classification | [history.py](../mayi/history.py), [recovery.py](../mayi/recovery.py) | [D09/D10](decisions/INDEX.md#d09-conservative-outcomes-and-no-automatic-replay) | Explicit correlations, no replay; [history tests](../tests/test_history_classification.py) |
| Live aggregate/watch | [queue_snapshot.rs](../executor/src/queue_snapshot.rs), [approval_status.py](../mayi/approval_status.py) | [status](user/OPERATIONS.md#live-statuswatchpreflight) | Snapshot not control; [counter tests](../executor/src/queue_snapshot_tests.rs) |
| Package and ABI | [tpa.json](../executor/package/tpa.json), [builder](../executor/package/build-deb.sh), [ABI gate](../executor/package/verify_abi.py) | [build](development/DEVELOPMENT.md#reproduction-and-release-boundaries) | Exact artifact identity/dependencies/hardening |
| Regression suites/manuals | [tests/](../tests/), [Rust tests](../executor/src/), [man/](../man/) | [qualification](qualification/QUALIFICATION.md) | Executable checks and operator reference, not unsupported proof |
| Disconnected filesystem core | [filesystem.rs](../executor/src/filesystem.rs) | [status](security/FILESYSTEM_EXECUTOR_STATUS.md) | Experimental only; [isolation](development/TEST_ISOLATION.md) does not enable it |

## Design Decisions

[Decision index](decisions/INDEX.md) links15 supported mechanisms/tradeoffs to
current contracts, code, tests and original investigations. It distinguishes
recorded earlier implementations from inferred engineering explanations and
accepted limitations. No fabricated rejected alternatives or new guarantees.

## Historical Research

[Historical index](historical/INDEX.md) owns scope and original-base link mapping:
[audits](historical/audits/AUDIT_REPORT_0.4.1-4.md),
[experiments](historical/experiments/README.md),
[source-era snapshots](historical/baseline-3b6/README.md),
[release freeze records](historical/releases/RELEASE_FREEZE_0.4.1-11.md) and
[former navigation/move map](historical/navigation-03318f6/INDEX.md).
Original content, failed candidates, partial results and corrected reruns are not
rewritten into successes. Research availability does not enable a feature.

## Known Limitations

[Limits/assumptions/unproven scope](security/LIMITATIONS.md) owns current boundaries:
consumption-time TTL, conservative unknown outcomes, no queue/capability recovery,
best-effort history, snapshot-only preflight,30x8 measured UI, stock Debian scope,
trusted host services, cached PAM tradeoffs and disconnected filesystem execution.
[Qualification](qualification/QUALIFICATION.md) owns what was actually tested.

## Documentation Authority

Qualified source/artifact identity anchors tested behavior. Implemented security
boundaries and executable checks describe actual enforcement; current documents
state intended contracts. If they disagree, investigate a correctness issue rather
than silently preferring either or weakening guarantees. Supporting root package
details are linked above; historical notes are scoped records, not alternate
current specifications. Tests remain in place even when old design notes move.
Update the one owning document and its links; do not create duplicate security
models or infer a general guarantee from a finite test suite.
