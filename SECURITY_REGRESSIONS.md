# Security regression assessment

PASS within tested scope. Original qualified authorization/execution models remain authoritative. Request/approval/consume/PAM/executor wire schemas, canonical digests, stored arguments, UID/NSS isolation, PAM identity checks, session idle/expiry, view one-shot semantics, consumption-time clocks, queue decisions and durable executor claim ledger are unchanged.

All existing source security regressions pass, including terminal supervisor success/failure/timeout/SIGTERM/SIGKILL, process/terminal-bound authentication sessions, replay, ownership, digest substitution, expiration and approval input safety. Existing Python stored-operation handoff guard is retained. Actual installed tests repeat PAM failures/child termination/recovery, explicit denial, one-shot replay/digest rejection, restart invalidation, >300-second expiration, actual native field privacy and package lifecycle.

Audit is immutable projection after the relevant state transition. No fallible logging result controls an authorization branch. The private completion-observation flag only names events based on an already validated executor response; no extra response field, grant, retry, cache, persistence or IPC metadata was added. Tests distinguish pre-spawn rejection from completion, and unknown outcomes remain unknown. A journald denial/drop cannot authorize a request: installed unavailable/rate-limit tests leave it pending until the existing explicit approval flow.

No body/argv/environment/output serialization or capability/session/view secrets are passed to the logger. Field names are fixed and values bounded/validated. Messages escape controls, and contextual identities derive from stored/kernel-verified state. Invalid/uncorrelated frames may have no attributable request ID; missing audit is not proof of rejection or nonexecution.

No requester journal-read privilege, new root endpoint, database, filesystem execution, policy admission or release operation is introduced. Same-UID/root compromise and malicious root programs can falsify audit assertions; trusted Journald metadata is useful attribution, not tamper-proof evidence. The intentional five-minute authentication trade-off inherited from 0.4.1-9 is not changed or rebranded as per-decision password proof. Queue persistence across broker restart and general exactly-once side effects remain NOT CLAIMED.


Tested runtime/package source commit: `08a4d259a6ae7e9a17afecb31ab3cd5b6d9a4724` (unsigned development commit; no release tag). Development package: `0.4.1-10~journald4 amd64`, SHA-256 `cfeb6844af4b50e55ff20003da05ee5a2a686bbdb5bcf793b64e9fa3e6aa2167`.
