# Security regressions — authenticated broker epochs

Decision support is in RESTART_SECURITY_TESTS.md, DEBIAN_MATRIX.md and
/home/eugen/projekte/mayi-qualification/restart-0.4.1-10-status4/independent-audit-final.json.

Existing exact executable/argv binding, trusted-directory policy, kernel peer
identity/NSS role separation, PAM/challenge/terminal/session binding, success-only
session renewal, one-shot root claims, strict selected-request consumption-time
expiry, response correlation and bounded best-effort native logging are retained.
No authority endpoint, approval replay, request replay, automatic retry, ACL/group
expansion, queue persistence, filesystem executor connection or Porta modification.

The new local 32-byte HMAC key authenticates request-ID origin only. A valid ID
does not restore a request, approve it, claim it or run it. Current RAM state,
matching instance/challenge/digest, owner and human approval still gate execution.
A wrong/missing key cannot establish old provenance; no hash-only inference or
legacy fallback is used. The key is not included in packages, IDs, metadata or
qualification evidence. Private-directory and key metadata are checked; unsafe
storage fails startup instead of rotating a key or recovering authority.

Limits retained or explicit:
* Cryptographic collision resistance is not a formal guarantee about arbitrary
  administrative VM/RNG snapshots. No sequential epochs are assumed.
* Interrupted first-key creation can leave a temporary hardlink and cause the
  strict nlink check to fail closed; no automatic repair or key replacement.
* Durability/retention of Journald is not guaranteed. Missing execution records,
  broker death and zero counters do not establish absence of side effects.
* A broker-only restart does not kill a separately supervised root child.
* No general exactly-once effects, execution-start TTL or queue recovery claim.
* Old clients with fixed rq_32hex assumptions must migrate to versioned IDs.
  Legacy history stays readable; no new legacy IDs are issued.
* GET_QUEUE_STATUS remains a successful read of known current terminal states,
  with canonical authorization_error classification; consumed challenge errors
  retain legacy flat aliases plus canonical nested error codes.
* --status --json guarantees the full structured authenticated epoch error;
  other pre-existing CLI validation/transport errors may still use stderr.
* History never authenticates IDs with the private key or queries live state.
  epoch_id is recorded identity, not a UI grant. Lifecycle invalidation is
  explicitly historical inference unless there is a per-request shutdown fence.

Original process failures and historical skips remain visible. This is a
qualified candidate, not authorization to deploy, publish, promote, sign or push.
