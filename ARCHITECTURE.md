# Mayi architecture (stable baseline 0.4.1)

Mayi is a local exact-command privilege broker. The requester does not hold root credentials; it submits a proposal. The human enters through a PAM-authenticated approval console. The broker owns request and approval state, and a separate privileged executor accepts only broker-authorized stored operations.

```text
agent / requester
        │ exact executable + argv
        ▼
Rust broker ── immutable request, peer-UID/NSS role checks
        │ fresh one-shot view
        ▼
human approval console ── approver-group check, then PAM on controlling TTY
        │ one-shot decision, actual peer UID
        ▼
Rust broker ── independently validates and consumes stored operation
        │ broker-UID-authenticated executor request
        ▼
privileged executor ── revalidates, journals one-shot claim
        │ direct exec; sanitized environment
        ▼
process as UID 0 / primary GID 23012
```

## Trust and request flow

1. `mayi` resolves a command name through fixed trusted system directories or accepts an absolute executable path. It sends one structured `exec` operation. Mayi does not pass requester environment, cwd, descriptors, or a shell command string. The resolved canonical executable path and supplied argv are separate stored values; the supplied command token is argv[0].
2. The Rust broker obtains peer credentials from `SO_PEERCRED`, resolves the UID through NSS, checks requester-group authorization, validates the closed schema and executable/argv bounds, and stores immutable request state bound to the actual requester UID. Client-provided approval fields do not grant authority.
3. Before any broker connection or request display, `mayi-approve` requires an interactive controlling TTY, checks the calling UID's NSS approver-group membership, then authenticates the same account through PAM service `mayi-approve`. Passwords are read from `/dev/tty` with echo disabled; argv, environment, and piped stdin are not credential channels. Successful authentication exists only in that console process.
4. The console fetches fresh broker-owned views and displays the executable, argv, requester identity and queue dependencies. The renderer is presentation only: its text is not execution input. Decisions are correlated with the fresh one-shot view and bound to the authenticated peer UID. Skip is local navigation only; deny and follow-up do not execute.
5. The broker independently validates peer UID/group/view/decision state. It consumes the immutable approved operation at most once. For a queued operation, dispatch additionally requires every dependency to have succeeded; a terminal unsuccessful dependency blocks descendants.
6. The executor authenticates the exact broker UID with `SO_PEERCRED`, revalidates the operation, journals the one-shot request ID before spawn, clears the inherited environment, and launches directly without shell mediation. It does not accept requester or approver authority as a path to execution.

## Synchronous and queued operation

The synchronous `mayi EXECUTABLE [ARG ...]` flow waits for approval and a result. `mayi --queue` returns a broker-generated opaque request ID immediately; each queued operation still needs explicit approval. `--after` binds dependencies to retained requests owned by the same requester UID. `--wait` and `--status` observe results only; `--fail-instant` does not cancel remaining work.

Queue records/results are held in broker memory. Persistence across broker restart is **NOT CLAIMED**; restart loses pending queue state and retained results, and Mayi does not replay requests. The executor's durable replay journal does not make broker queue state persistent.

## Security limits

The human approves a process and exact argv, not a semantic interpretation. Mayi does not prove that a root-owned executable or its arguments are safe. An explicitly requested shell can interpret its own input. `SO_PEERCRED` identifies an OS UID, not a process or human, and cannot distinguish processes sharing an account. PAM authenticates the account entering the console but does not replace broker peer checks, role authorization, or request/view binding.

Execution is at most once, not transactional: a command may partially change system state before failing or losing its response. Mayi does not provide rollback, and the child has no runtime deadline. The filesystem executor remains **DISCONNECTED / INCOMPLETE**; structured filesystem operations are not enabled for privileged execution.

See [`SECURITY_BOUNDARY.md`](SECURITY_BOUNDARY.md) for the guarantee/trust distinction, [`PROTOCOL.md`](PROTOCOL.md) for message and state details, and [`man/mayi-workflow.7`](man/mayi-workflow.7) for operator steps.
