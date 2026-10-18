# Limits, assumptions and unproven properties

Current supported qualification is stock Debian11/12/13 amd64. Security depends
on trusted kernel/NSS/PAM/systemd/root/broker/executor and protected service files.
A compromised trusted service/root or same-UID console control is not defeated.
PAM's fixed cgroup/service configuration is part of the tested boundary.

- Exact human authorization is not semantic command safety, transactional rollback
  or general exactly-once execution/effects. Explicit shells retain their power.
- Request/view/session expiry, claim and physical start are distinct. TTL is at
  consumption/dispatch claim; execution can start later, no child-runtime deadline.
- No queue/result/session/capability restoration; provenance-key persistence never
  recreates authority. Lost/unsafe key fails closed, not automatic repair/recovery.
- Restart invalidates authority but may leave physical root/PAM work. Missing logs,
  state or replies mean uncertainty, not safe retry. Reconciliation is external.
- Journald delivery/retention is best effort; history is bounded historical evidence,
  not live broker state or cryptographically complete audit. No guessed joins.
- Status running is broker-observed spawn, not OS census. Preflight READY is a snapshot,
  not admission fencing, physical idleness or restart authorization.
- Current console sessions are successful-decision-only sliding five-minute state.
  Cached decisions repeat account policy, not authentication-stack password/MFA checks.
  Per-process/terminal binding does not defeat compromise of that process/account.
- Approval geometry measured at30x8 or larger. Plain/full details can use scrollback;
  too-small ANSI detail watch refuses with visible fallback. Unknown geometry80x24
  is a default, not measured viewport. Human nonce aliases are not lookup tokens.
- Filesystem execution remains DISCONNECTED / INCOMPLETE. Live non-exec proposals
  fail before admission; direct-core unit tests do not enable the feature.
- Other platforms/architectures, Synology/custom PAM/MFA/SSSD, physical suspend and
  independent compiler/bootstrap/hermetic bare-host rebuild remain unqualified.
  Session clock-model tests are not physical suspend tests.

ui2 resolved supported-screen overflow, hidden executor, noisy status, shared-epoch
human IDs, narrow waiting, unsized watch, invisible advice and unbounded notices;
these obsolete UI warnings are historical, not current blockers.

Bounded output retention/retrieval, Porta recovery integration, more usability,
platform support and execution extensions remain possible future requirements.
None is implemented here or permanently rejected. No speculative roadmap is needed.
Source/doc disagreements require investigation; do not expand a guarantee to fill
a documentation gap. [Qualification](QUALIFICATION.md) defines actual tested bounds.
