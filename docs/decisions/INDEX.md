# Design decisions and rationale

This is a navigation index, not a new set of security requirements or invented
ADR history. Current contracts live in [the security model](../security/SECURITY_MODEL.md)
and [architecture](../architecture/ARCHITECTURE.md). Evidence below records what
was investigated. Where no alternative or original deliberation was recorded,
that absence is stated; an engineering explanation is not a historical quotation.
[All documentation](../INDEX.md#why-does-this-exist).

## D01 Peer identity, not caller assertions

**Decision/purpose:** bind roles and request ownership to kernel peer UID plus NSS,
not JSON approval/UID fields. **Constraint/consequence:** socket ACLs alone are
insufficient; trusted kernel/NSS/root and same-account limitations remain.
**Alternatives:** no broader identity-design comparison is recorded here.
**Basis/status:** implemented current contract: [binding](../security/SECURITY_MODEL.md#binding-and-enforcement),
[broker](../../executor/src/broker.rs), [negative identity tests](../../executor/src/broker_security_tests.rs).

## D02 Stored exact operations, not rendered commands

**Decision/purpose:** approve and execute the broker's immutable executable/argv;
never parse renderer output into execution input. **Constraint/consequence:**
a display is review notation, not a shell-safety proof; an approved interpreter
can execute its own supplied code. **Alternative explicitly excluded:** implicit
shell-string execution. **Basis/status:** current [architecture](../architecture/ARCHITECTURE.md#execution-not-semantic-analysis),
[client](../../mayi/executor.py), [dispatch tests](../../tests/test_cli_dispatch.py).

## D03 One-way consumption and root claims

**Decision/purpose:** serialize the selected approved request's one-way claim and
bind root execution to that stored operation. **Constraint/consequence:** one
successful claim under contention, not general exactly-once effects or rollback.
**Alternatives:** no claim that every alternative design was evaluated.
**Basis/status:** current [lifecycle](../security/SECURITY_MODEL.md#distinct-objects),
[broker tests](../../executor/src/broker_security_tests.rs), [root executor](../../executor/src/bin/mayi-privileged-executor.rs),
[final race evidence](../qualification/QUALIFICATION.md#tested-scope-not-universal-proof).

## D04 PAM enforcement outside the console

**Decision/motivation:** old console-local PAM could be bypassed by a direct
approval-socket client; broker-mediated PAM makes successful human authentication
part of the accepted decision boundary. The unprivileged broker delegates the
privileged account interaction to a narrow helper, not a requester assertion.
**Documented earlier alternative:** console-only PAM, rejected by the historical
audit. **Constraints/consequences:** exact UID/correlation, TTY, fixed service
identity and stock PAM scope; helper/root/systemd remain trusted.
**Basis/status:** [historical candidate4 audit](../historical/audits/AUDIT_REPORT_0.4.1-4.md),
[current authentication](../security/SECURITY_MODEL.md#authentication-is-not-request-authorization),
[helper](../../executor/src/pam_auth.rs), [PAM tests](../../executor/src/pam_security_tests.rs).

## D05 Per-process sliding console authentication

**Decision/purpose:** authenticate a console once, then allow explicit decisions
within a five-minute successful-decision-only idle session bound to process and
terminal. **Documented alternative:** repeated password authentication on each
legacy decision, retained for clients without sessions. **Tradeoff:** cached
decisions repeat account policy, not password/MFA authentication-stack checks;
a compromised/unattended unlocked console is not protected by token binding.
**Basis/status:** [original session design and limits](../historical/baseline-3b6/AUTHENTICATION_SESSIONS.md),
[current contract](../security/SECURITY_MODEL.md#authentication-is-not-request-authorization),
[session implementation](../../executor/src/console_sessions.rs), [tests](../../executor/src/console_session_tests.rs).

## D06 Check expiry at the selected transition

**Decision/purpose:** sample the selected request's deadline under the claim lock,
not rely on an earlier housekeeping sweep that can become stale during delays.
**Constraint/consequence:** strict consumption-time validity, not child-start TTL;
view/session/request expiry are distinct. **Documented excluded mechanism:**
preliminary broad sweep as the sole authorization check.
**Basis/status:** [expiration](../security/SECURITY_MODEL.md#expiration-and-dependencies),
[deadline regressions](../../executor/src/broker_deadline_tests.rs), [broker](../../executor/src/broker.rs).

## D07 Epoch-bound authenticated request identities

**Decision/purpose:** preserve authentic stale-ID provenance while refusing old
broker authority. **Alternative explicitly excluded:** infer a restart merely
from missing RAM state or trust caller-supplied epoch data. **Constraint:** the
persistent HMAC provenance key is not persisted queue/capability authority;
key loss/unsafe files fail closed. **Consequence:** a genuine stale ID still says
UNKNOWN about side effects, not safe replay.
**Basis/status:** [epoch details](../../BROKER_EPOCH.md), [IDs](../../executor/src/request_ids.rs),
[shutdown](../../executor/src/broker_epoch.rs), [epoch tests](../../tests/test_epochs.py).

## D08 Memory-only queue is the qualified boundary

**Decision/status:** current queues/results/approvals are not restored after
restart; only ID provenance persists. **Why it matters:** a consumer must not
reconstruct authority from historical observations. **Historical motivation:**
a broader persistence design discussion is not established by these records.
Do NOT claim persistence is inherently unsafe or permanently rejected.
**Alternatives:** persistent recovery remains unqualified, not implemented here.
**Consequences/basis:** [restart contract](../security/SECURITY_MODEL.md#epoch-restart-and-conservative-outcome),
[recovery guidance](../../PORTA_RECOVERY_CONTRACT.md), [epoch regressions](../../executor/src/broker_epoch_tests.rs).

## D09 Conservative outcomes and no automatic replay

**Decision/purpose:** separate authorization claim, actual start and final outcome.
A lost reply/dead broker can coexist with a running or completed root child.
**Excluded inference:** missing state/logs means nothing happened and is safe to
retry. **Consequence:** reconcile uncertain effects; no exactly-once promise.
**Basis/status:** [outcome semantics](../../EXECUTION_OUTCOME_SEMANTICS.md),
[recovery classifier](../../mayi/recovery.py), [history tests](../../tests/test_history.py),
[installed residual-child evidence](../qualification/QUALIFICATION.md#tested-scope-not-universal-proof).

## D10 Bounded native audit and journal-backed history

**Decision/purpose:** emit correlated typed events through existing Journald and
project them with existing unprivileged journal permissions, without creating
another privileged history authority. **Constraints:** bounded best-effort writes,
no secrets/payload projection, explicit missing/ambiguous correlation.
**Alternative avoided in the recorded implementation:** a separate history
collector/database or authority-recovery cache; not a universal database comparison.
**Basis/status:** [audit/history](../user/OPERATIONS.md#native-audit-and-history),
[audit source](../../executor/src/audit.rs), [correlation](../../HISTORY_CORRELATION.md),
[classification regression](../../tests/test_history_classification.py).

## D11 Observe running work without controlling admission

**Decision/motivation:** queue RUNNING was a dispatch claim, not proof of child
spawn. A correlated optional root start frame gives a truthful observed-running
counter. A bounded synchronous observation map avoids extending authorization
retention just for statistics. **Excluded inference:** process census or an idle
lock from aggregate counts. **Consequence:** preflight is read-only snapshot,
not restart authority. **Basis/status:** [recorded status design](../../STATUS_DESIGN.md),
[snapshot](../../executor/src/queue_snapshot.rs), [tests](../../executor/src/queue_snapshot_tests.rs),
[preflight](../../UPDATE_PREFLIGHT.md).

## D12 Bounded review without changing execution order

**Decision/motivation:** actual UX audit found overflowing review chrome and
context before actionable rows. Bounded pages/notices and pending-first rendering
keep controls/executor visible while retaining original indices and the current
bound selection. **Documented earlier implementation:** verbose overflowing UI,
not a rejected terminal-framework comparison. **Consequence:** full inspection
may require paging; display cannot prove a human saw every argument.
**Basis/status:** [initial UX audit](../historical/baseline-3b6/UX_AUDIT.md),
[current controls](../user/OPERATIONS.md#human-approval-and-waiting),
[renderer](../../executor/src/approval_ui.rs), [PTY tests](../../executor/src/ui_pty_tests.rs).

## D13 Metadata dispatch must not reinterpret child argv

**Decision/purpose:** handle sole leading version/help locally and use the first
-- as unconditional executable dispatch; after executable, flags are child data.
**Documented excluded alternative:** reserving bare version would break an
existing executable name. **Consequence:** metadata does not require broker/PAM,
execution still requires exact approval. **Basis/status:** [dispatch design](../../CLI_DISPATCH_DESIGN.md),
[metadata](../../mayi/cli_metadata.py), [dispatch regressions](../../tests/test_cli_dispatch.py).

## D14 Source presence does not enable filesystem execution

**Decision/status:** keep the incomplete filesystem core outside qualified live
execution; reject non-exec proposals before pending admission. **Constraint:**
prototype/syscall tests do not establish production readiness. This is a current
scope limit, not a permanent rejection of future filesystem requirements.
**Earlier investigations:** [filesystem qualification](../historical/experiments/filesystem/FILESYSTEM_EXECUTOR_REMEDIATION.md).
**Basis/status:** [current status](../security/FILESYSTEM_EXECUTOR_STATUS.md),
[broker rejection tests](../../executor/src/broker_security_tests.rs), [experimental core](../../executor/src/filesystem.rs).

## D15 Asynchronous requests and dependency waiting

**Mechanism/purpose:** return a queued request ID before human approval/execution,
then let observers wait without authorizing or replaying work; approved children
also wait for successful prerequisites. **Rationale label:** the workflow purpose
follows from the documented API, not a reconstructed historical alternatives study.
**Constraints/consequences:** each request still needs explicit approval, same-owner
dependencies, bounded memory and conservative restart handling. No fairness or
completion-time guarantee follows. **Basis/status:** [queue protocol](../architecture/IPC_PROTOCOL.md),
[requester operations](../user/OPERATIONS.md#local-metadata-and-exact-argv),
[client](../../mayi/cli.py), [queue/status tests](../../tests/test_approval_status.py).
