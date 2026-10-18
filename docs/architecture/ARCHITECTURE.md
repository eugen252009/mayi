# Architecture

See [security/lifecycle](../security/SECURITY_MODEL.md) for guarantees and [protocol](IPC_PROTOCOL.md)
for wire contracts. This document owns component boundaries, not duplicated policies.

## Components

| Component | Implementation | Authority / trust boundary |
|---|---|---|
| Unprivileged requester | [cli.py](../../mayi/cli.py), [executor.py](../../mayi/executor.py) | Proposes canonical executable plus exact argv; no grant from submission |
| Human console | [approval_cli.py](../../mayi/approval_cli.py), [approval_ui.rs](../../executor/src/approval_ui.rs) | Interactive explicit decisions; display is never execution input |
| Authorization broker | [broker.rs](../../executor/src/broker.rs) | Owns immutable request, view, approval, queue, session and atomic one-shot transition |
| PAM authority | [pam_auth.rs](../../executor/src/pam_auth.rs) | Authenticates/account-checks broker-derived UID through a controlling TTY |
| Root executor | [privileged-executor](../../executor/src/bin/mayi-privileged-executor.rs) | Accepts trusted broker only, validates exact stored operation and one-shot claim, spawns child |
| Kernel/NSS/PAM/systemd | Host trusted computing base | Peer credentials, account/role lookup, terminal/process identity, service containment |
| Audit/history/status | [audit.rs](../../executor/src/audit.rs), [history.py](../../mayi/history.py), [queue_snapshot.rs](../../executor/src/queue_snapshot.rs) | Bounded observation, not authorization or a recovery plane |
| Porta/other clients | Separate projects | Use public request/status semantics; no privileged direct access or authority reconstruction |

Python also retains compatibility inspect/check modeling; it is advisory, not a
privileged operation path. [filesystem.rs](../../executor/src/filesystem.rs) is
DISCONNECTED / INCOMPLETE; having source and unit tests does not enable it.

## Installed identities

Default requester group23011, approver group23013; broker account UID23002,
primary broker-socket GID23012. Broker is unprivileged. PAM helper and privileged
executor are separate root services; approved children run UID0/primary GID23012,
not the proposal's target metadata. Root/systemd and trusted service identities
are assumptions, not adversaries defeated by Mayi.

The broker accepts requester and approval sockets separately. PAM authority
accepts broker UID and the fixed /system.slice/mayi-broker.service cgroup;
the root executor independently checks broker UID. Socket ACLs are defense in
depth, never substitutes for kernel peer UID/NSS validation. Local processes
sharing a trusted UID or controlling the authenticated console are outside
strong same-account isolation claims.

The PAM helper is bounded to CAP_DAC_READ_SEARCH with NoNewPrivileges and
systemd sandboxing. The executor intentionally has broad approved-command
privilege. See actual [units](../../executor/package/usr/lib/systemd/system)
and [maintainer scripts](../../executor/package/DEBIAN) for enforced settings.

## Execution, not semantic analysis

Mayi executes an explicitly approved program/argv as root. It neither interprets
shell strings implicitly nor proves the chosen program safe. An approved shell
can interpret its own arguments. The executor uses cleared/fixed environment,
cwd / and stdin /dev/null; output is bounded. It does not impose a child-runtime
deadline. IPC timeout or a dead broker need not stop physical work.
