# Mayi security boundary — stable baseline 0.4.1

## Guarantees implemented by the qualified package

- **Broker-owned request state:** the broker validates and stores the exact resolved executable path and argv. Requester-supplied approval fields, rendered text, environment, cwd, and file descriptors are not execution authority/input.
- **Independent identity and role checks:** broker request/approval peers are authenticated using kernel `SO_PEERCRED`; requester and approver roles are checked against NSS groups. The executor separately accepts only the configured broker UID.
- **Human approval gate:** before connecting to the broker or displaying requests, `mayi-approve` requires an interactive controlling TTY, checks the actual caller's approver-group membership, and authenticates that same account through PAM. Passwords are read from the terminal with echo disabled, not from argv, environment, or piped stdin. Authentication is process-local.
- **One-shot decision lifecycle:** a decision uses a fresh broker view and is bound to the request and actual approver UID. The broker consumes approved state at most once. For queues, each operation needs approval and all dependencies must succeed before execution.
- **Exact process execution:** only the broker's immutable `exec` operation reaches the privileged executor. The executor repeats validation, records a one-shot replay claim, clears the environment, and launches the executable directly with argv—no implicit shell.
- **No direct requester/approver executor path:** the executor socket authenticates the broker UID. Socket access alone is not authorization.
- **0.4.1 console UX:** successful authentication is quiet. After a fully correlated successful allow/deny/follow-up decision, supported TTYs clear only the visible screen; scrollback is preserved. Failed decisions preserve the display.

## Trust assumptions and non-goals

`SO_PEERCRED` authenticates an OS UID, not a binary, process, or human. Processes sharing a UID are not distinguished. PAM authenticates the account entering the console; it does not replace broker peer credentials, NSS role checks, request/view binding, or one-shot decisions. The broker, executor, root-owned executable directories, host PAM/NSS configuration, and system account/group administration are trusted.

Mayi is broad human-gated root execution, not a command allowlist or semantic safety engine. Approval does not prove that a program, shell, or argument is safe. Execution is at most once, not transactional: a command can partially alter system state before failing or producing an ambiguous result. There is no rollback or child runtime deadline.

Queue and result persistence across broker restart is **NOT CLAIMED**. Queue state/results are in broker memory and are lost on restart; no requests are replayed. The privileged executor's one-shot journal is not durable queue storage.

The filesystem executor is **DISCONNECTED / INCOMPLETE**. Structured filesystem operations remain disabled and are not production functionality. Its historical design/qualification records are archived under [`docs/history/filesystem/`](docs/history/filesystem/); they are not evidence that filesystem execution is supported.

## Installed identity and PAM boundary

The Debian package uses broker UID/GID 23002/23012, requester group `mayi-requester` GID 23011, approver group `mayi-approver` GID 23013, and executor UID 0 / primary GID 23012. Package installation does not add human users to role groups. The administrator must check ID collisions and grant only intended memberships.

PAM service `/etc/pam.d/mayi-approve` includes the host's common authentication and account policies. Missing, unsafe, rejecting, or unusable PAM configuration fails closed. The package requires glibc >=2.28, Python >=3.7, and the PAM runtime dependencies recorded in the package metadata. See [`DEBIAN_COMPATIBILITY.md`](DEBIAN_COMPATIBILITY.md) for technical floors, qualified Debian releases, and EOL guidance.

## Stable release evidence

The current stable release is **0.4.1**, amd64, qualified on Debian 10–13 in disposable systemd environments. Its exact artifact SHA-256 is `22409abd977d4d14113ee34e47ed78f94a4e975da84e9606f5fe704116f59ab0`. It was published through TPA.run/bootstrap and independently hash-checked through APT. Publication is not deployment. Detailed evidence is in [`MVP_QUALIFICATION.md`](MVP_QUALIFICATION.md).
