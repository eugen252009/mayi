# Status security regression results

PASS in the tested scope. Same kernel credential/NSS approver checks and existing approval socket permissions. No new root service, general inspection endpoint, executable policy, role, token/session or privilege. QUEUE_STATUS requires strict type/protocol-only frame, no supplied UID/scope, no terminal FD; requester socket/role rejected. Authorized global count visibility is narrower than existing LIST_PENDING.

Snapshot reads one locked state with one monotonic sample; no expire/scheduler/session/view/consume mutation. Socket output after unlock. Unit tests and installed pending polling verify no PAM/session/approval effects. Status successes do not add audit noise; invalid role lookup retains original diagnostic only. Counts never include payload/argv/UID lists/secrets; strict client schema prevents untrusted display controls and bool/negative/inconsistent counters.

The existing internal executor protocol has a necessary opt-in same-body request variant and one post-spawn observation, not a new authority source. Root still authenticates UID23002, validates exact root-owned executable/argv and durably claims once before spawning. Notification uses one nonblocking send (no waits/retries), does not alter child lifecycle/result, and does not authorize anything. Broker root-peer/ID/schema checks correlate the notice; final response still mandatory with original absolute300s timeout. Lost/malformed data remains unknown, never retries/falls back. Legacy EXEC_REQUEST still works; mixed new broker/old root helper fails closed.

135+10 Rust,147 Python +9 explicit SKIP, fmt and strict Clippy PASS. Actual installed Debian11/12/13 repeat one-shot, identity isolation, exact operation binding, replay/digest/role rejection, strict real consumption expiry, explicit approval, real PAM failure/worker kill/recovery/terminal safety, logging unavailable/rate limit and history/no-recovery behavior. FS executor remains DISCONNECTED/INCOMPLETE; no queue persistence or general exactly-once effects claimed.

Synchronous observations remain <=8 request workers and survive existing consumed-record cleanup without changing authorization quotas/retention; they disappear on RPC completion/restart. Known dispatch/running are not guesses from journals. Unknown outcomes/restart can leave residual physical execution; these counters are broker observations, not full OS process supervision.


Tested package source: 90a65fd6d8432f5b6c1e297b24dc91bd80a18f1a. Development 0.4.1-10~status1 amd64. First/rebuild SHA-256: 4ce927013fb811ffa21d9540ac007ff5f47cfff1d9f0c8d2fe3f8e6632e3aab4.
