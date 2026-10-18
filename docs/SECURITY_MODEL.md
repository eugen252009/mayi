# Security model and request lifecycle

Scope: current exact-command implementation inherited byte-for-byte from qualified
0.4.1-11. [Qualification](QUALIFICATION.md) separates TESTED scope from assumptions.
No ambient grant, automatic approval or replay is introduced by consolidation.

## Distinct objects

| Object | Meaning / lifetime |
|---|---|
| Request | Broker-owned exact operation, requester UID, digest, epoch and deadline; pending is not approved |
| Approval view | Fresh broker-generated one-shot binding to request/digest/approver; at most60s and no longer than request validity; replacing/expiring it is NOT request expiry |
| Console PAM session | Per-process/terminal authenticated transport state; never approval of a request |
| Approval / capability | Explicit permitted transition for the immutable request, still subject to ownership/deadline/one-shot checks at consumption |
| Consumed claim | Irreversible authorization transition, not proof of spawn, completion or success |
| Child outcome | Correlated actual execution observation, separate from authorization state |

A rendered view does not prove a human read or understood it. Explicit accepted
decision is the authorization event; authentication alone authorizes no command.

## Binding and enforcement

Kernel SO_PEERCRED UID plus NSS roles bind requester/approver. The request stores
canonical executable and complete argv (including argv0); consume accepts the
bound instance/challenge/digest, not replacement operation data. Executables and
path components must satisfy fixed trusted-directory/root-ownership/non-writable
rules. Relative paths, unknown schemas/fields, unsupported operations, malformed
IDs and substituted ownership/digests fail closed. Request target metadata does
not select root execution identity.

Broker state is protected by its mutex. After authentication/account checks and
role revalidation, approval rechecks selected request/view deadlines at transition.
Consumption/queue claim makes the final selected monotonic deadline check under
that lock: equality is expired, then one-way claim and stored-operation handoff.
A broad housekeeping expiry sweep is not the security check.
The root executor separately claims the broker-derived execution ID before spawn;
duplicate/uncertain claims are never automatically retried.

## Authentication is not request authorization

The current console runs full pam_authenticate and pam_acct_mgmt before showing
requests; secrets stay in PAM/TTY, not JSON/argv/environment. Authentication is
bound to kernel UID/PID, retained pidfd, terminal identity and broker epoch.
Only a successful explicit approve/deny/follow-up resets the five-minute sliding
idle session. Listing, viewing, paging, input and status/preflight reads do not
renew it. Session checks use monotonic and suspend-aware boottime clocks;
physical suspend remains outside installed qualification.

Cached decisions still require exact request/view binding, live session,
terminal, NSS role rechecks and PAM ACCOUNT policy. They do not repeat password
authentication. Password/MFA restrictions enforced only by the authentication
stack may not immediately revoke an existing session. Account-only prompts fail
closed. Legacy decisions WITHOUT a session use full per-decision PAM; an invalid
provided session never silently falls back. Exit/death/hangup/restart invalidates
authentication; restarting a console never restores it.

## Expiration and dependencies

Ordinary requests have300s lifetime; queued requests retain the existing24h
lifetime and bounded storage. View expiry, request expiry, session idle expiry,
PAM timeout and execution IPC timeout are different clocks/objects. Expiring a
view is not an EXPIRED request; a spent capability is not a new expired request.
The enforced authorization TTL is at consumption/dispatch CLAIM, not child start
or response delivery. A valid claim can start later. Request TTL uses process-local
monotonic time; do not inherit the session's boottime claim for all TTLs.

Queued requests require individual approval and successful prerequisites.
Dependencies are same-requester, immutable and checked for invalid/cyclic graphs.
Pending-first renderer order and unchanged displayed indices do not change broker
dependency execution order. Skip/quit/navigation are not denial or cancellation.

## Epoch, restart and conservative outcome

[broker_epoch.rs](../executor/src/broker_epoch.rs) fences shutdown claims under the
same mutex. Only demonstrated unclaimed idle pending/approved requests receive
pre-claim invalidation evidence. Consumed/dispatching/running/uncertain work must
not be labelled safely unexecuted. Crashes cannot promise a stopping record.

Each broker starts a fresh192-bit epoch. Memory-held requests/views/approvals/
sessions are not restored. The private32-byte request-ID provenance key persists,
not authority. Authenticated old rq_v2 IDs can prove old authority invalid but
cannot prove execution absent. Forged/lost-key/current-missing identities fail
closed without reconstructing RAM state. See [epoch details](../BROKER_EPOCH.md).

Root child start, completion and definitive rejection are distinct observations.
A broker restart, missing log, timeout or lost reply never proves failure or safe
retry. [recovery.py](../mayi/recovery.py) classifies evidence only; it performs no
IPC, replay or authority restoration. Reconcile uncertain side effects externally.
One-shot authorization is NOT a general exactly-once execution/effect guarantee,
transaction/rollback, OS process census or promise that physical work stopped.
