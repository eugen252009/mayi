> Archive view: maintainer-local paths have been omitted. Commands containing
> `[local-only path omitted]` are historical records, not runnable instructions.
> Original bytes remain at the commit/path recorded by the documentation checker.

# Mayi: STABLE — ACTIVELY MAINTAINED

Mayi 0.4.1-11 is the qualified stable development baseline. Current functional
requirements are satisfied, the software is actively used, and no additional
feature is immediately required. This is a development milestone, not an end
of development, a runtime mode or a deployment instruction. The release is
immutable; the project remains open to justified evolution.

## Reference identity

- Frozen release commit: `c5477fb19e1b979be980b451b6242e3565c9425a`.
- Package: `mayi_0.4.1-11_amd64.deb`, SHA-256
  `5499b09620b91ba4770d402e054600117a52a98448cc0d486b7f3d1fe6a3b899`.
- Source archive SHA-256:
  `f9ed636fbb49b99acab3f5fb034b0823b07aa465a0a079edc0e1b1a3f33273f4`.
- Bundle `[local-only path omitted]`, manifest SHA-256
  `4ee91e3b78bcf33d306c56ada8992f31e0d68060e6cf98c9c21a9c9b2db75722`.
- Final evidence: `[local-only path omitted]`;
  bundle-local reports: `evidence/reports/`.

Qualification covers Debian11/12/13 amd64 (44/44 installed gates and a separate
3/3 full package/CLI supplement per platform), 242 Python passes, 159 Rust passes,
nine documented historical skips, PAM/terminal recovery, Journald/history/status,
epoch/restart safety, reproducibility and ABI/hardening. Concurrency:60 races,
480 attempts,60 successful consumptions,60 markers,zero duplicates. Failed
fixture setups and corrected independent runs remain recorded, not relabelled.
The operator accepted ui2's interface; final-version automated tests are separate.

The frozen commit is **unsigned**. Verification of the trusted signed ancestor
is not a signature on that commit. Central release-tag/artifact/repository
signing, any required source attestation, admission, staging, upload and
publication remain separate. A source Git push is not Debian publication.
This status document is post-release documentation, not part of the qualified
release identity. Do not amend/rebuild historical identities to include it.

## Continuing development

Fix confirmed vulnerabilities, reproducible correctness/race/error-handling
issues, demonstrated usability problems, relevant compatibility needs and
measured performance bottlenecks. New capabilities remain welcome when a real
use case justifies practical value, security impact, maintenance cost,
architectural fit, testability and compatibility with existing guarantees.
Feature completeness is a current assessment, not a permanent restriction.
There is neither an obligation to add features nor a prohibition on doing so.

Start future branches from the frozen baseline or an explicitly qualified
successor; documentation descendants on the authoritative remote main retain
that baseline in their ancestry. Do not reset/pull over unsaved local work.
Define a concrete problem and acceptance criteria, inspect the implementation,
make the smallest appropriate change, add focused regression tests, run affected
functional/security tests, qualify relevant Debian targets, reproduce exact
source/package identities and assemble `[local-only path omitted]`.
Leave subsequent admission/staging/signing/publication to the central workflow.
Do not create releases merely because time passed; avoid unnecessary complexity.

Preserve explicit human approval/PAM, exact operation binding, requester
isolation, no ambient grants, one-shot claims, replay rejection, strict
consumption-time expiry, epoch invalidation, conservative outcomes, fail-closed
authorization, terminal safety and auditability. No automatic authorization or
replay. Changes to these invariants need deliberate architectural review and
independent security qualification.

Journald is best effort; history is not live authority. READY is a snapshot, not
an admission lock or OS process census. Restart does not prove physical work
stopped. Uncertain side effects require reconciliation; no general exactly-once
effects or start-time TTL is claimed. No queue/capability recovery is claimed.
Approval is measured at30x8 or larger; plain output can use scrollback.
Filesystem execution remains DISCONNECTED / INCOMPLETE; other platforms/custom
PAM and physical suspend are outside current qualification. Synology is not
supported. These are scope statements, not permanent rejection of future needs.

Bounded result storage, asynchronous output retrieval, Porta restart integration,
further usability/platform work and execution-architecture extensions remain
possible future ideas, not commitments or a speculative roadmap. None is
implemented by this documentation milestone. No runtime, service, PAM,
authorization, capability or configuration behavior changes with this status.
