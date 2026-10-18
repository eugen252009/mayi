# Independent final security audit — Mayi 0.4.1-6

## Verdict

**GO — exact artifact authorized for manual TPA.run publication.**

This verdict applies only to `mayi_0.4.1-6_amd64.deb`, SHA-256
`dac2e40bbc073f991fb99ce382d97e1ae68bf50b3f1f6fb8f42bca1864e45d38`,
on the documented Debian 11–13 amd64 platforms, with the documented stock local
Debian PAM and systemd/service-identity assumptions. It is not authorization for
deployment, a rebuild, another artifact with the same version, or filesystem execution.
No confirmed release-blocking defect was found in this review.

New independent evidence: `../mayi-qualification/independent-final-audit-0.4.1-6/`.
This review used source inspection, independent artifact extraction/hash comparisons,
retained raw evidence checks, and fresh installed-package QEMU executions; it did
not treat the release report or its PASS labels as proof.

## 1. Artifact, source and binaries

- Independently calculated candidate SHA-256 before and after review: exact match.
  Metadata: package `mayi`, version `0.4.1-6`, architecture `amd64`, 505392 bytes.
- Inspected both native binaries, launchers, Python payload, all four control
  scripts, PAM conffile, three systemd units, tmpfiles policy and compressed manpages.
  Package payload entries are root-owned; regular files are 0644 or executable
  0755, directories 0755. No packaged setuid/setgid executable was found.
- Extracted launchers, Python modules, units, tmpfiles, PAM policy, copyright,
  maintainer scripts and decompressed manpages match the current corresponding
  source files byte-for-byte. The generated preinst is shell setup only.
- Verified `source/SHA256SUMS`; archived runtime Rust sources and Cargo.lock match
  the reviewed tree. Independently read the retained Debian 11 builder through
  unprivileged SSH: all five Rust source files and Cargo.toml/Cargo.lock match;
  its two release binaries match the extracted candidate binaries exactly:
  - `/usr/bin/mayi-executor`: `ca3c7ddf0ff7efb9bcd1be794a4c112fbf38e2871a3b105b8b5b0fa5029019d8`
  - `/usr/libexec/mayi/privileged-executor`: `f70c957407fe759f79fafb9e0e8047b221db09e828347b0809ee74e807233d9a`
- In the fresh primary guest, independently hashed all 23 installed regular
  payload files and checked their ownership/modes against the candidate; all match.
  This check does not rely on `dpkg -V`, which is not a complete payload-integrity
  check for this package without a full md5sums inventory.
- Both native binaries have PIE, BIND_NOW/RELRO and non-executable GNU_STACK.
  Required GLIBC symbols reach 2.30. Supported releases provide compatible libc.
- Build provenance is a retained dirty-tree snapshot and builder outputs, not a
  signed attestation or an independently reproduced build. No rebuild was performed.

## 2. Approval path and F1

Reviewed `executor/src/broker.rs` gate, network dispatch, view validation, decision
transitions, consumption and executor handoff, plus `pam_auth.rs` authentication.
All three decision operations (approve, deny, explain) pass these gates:

1. Kernel `SO_PEERCRED` identity; initial NSS role authorization must return success.
2. Strict request schema, current broker instance, active request and unexpired
   view validation before PAM.
3. Exactly one terminal descriptor; broker-side helper authentication must explicitly
   return true on a correlated response from a UID-0 peer. Helper requires trusted
   broker UID/service cgroup, validates its own privileges and PAM configuration,
   resolves the peer UID through NSS, and requires successful PAM start/item setup,
   authentication, account management and end. PAM username and UID mapping are
   checked against substitution.
4. Final NSS role authorization must return success after authentication.
5. Under the broker mutex, revalidate instance/challenge/digest/view/approver UID,
   view lifetime and pending request state.
6. Mutate request/view state while holding that mutex. Consumption similarly claims
   approved state under the mutex before any privileged execution handoff.

**F1 correction confirmed for the reviewed source and installed artifact:**
`approval_authorization_gate` uses explicit Result propagation and requires an
explicit true authentication result. `pam_authenticated` starts false and is set
only when the entire gate succeeds. Dispatch has an independent rejection branch
for decisions lacking successful authentication. An absent error from a skipped
step cannot substitute for authentication. Initial authorization, preflight, PAM
or final authorization failure cannot fall through into `authority`.

Independent installed tests rejected missing PAM, failed/locked credentials and
initial/final NSS denial; recovery required fresh successful authentication.
The retained gate unit regression and all 33 broker unit tests independently passed.

Documentation precision: the final NSS lookup is immediately **before acquiring**
the broker state mutex, not inside it as some boundary prose states. State/binding
validation and transitions are inside the mutex. That mutex does not serialize
administrator NSS updates in either design; this is not an atomic NSS-revocation
guarantee. This discrepancy did not establish a bypass or release blocker.

## 3. Privilege separation

- Fresh guest broker: UID/GID 23002/23012; permitted/effective/inheritable/ambient
  capabilities zero; NoNewPrivileges=1. Its capability **bounding set is not zero**
  and the unit does not explicitly set an empty CapabilityBoundingSet. This is a
  defense-in-depth opportunity, not evidence of current effective privilege.
- PAM authority: UID 0/GID 23012, all five capability sets exactly
  CAP_DAC_READ_SEARCH, NoNewPrivileges=1; strict/read-only filesystem sandbox,
  restricted namespaces/kernel interfaces, writable PAM socket/faillock paths.
  It remains privileged code able to read protected data; host PAM modules are trusted.
- Helper requires both broker UID and protected exact service cgroup membership
  (including descendants). No executable-path attestation is claimed. Fixed
  systemd cgroup placement and trusted root/systemd administration are prerequisites.
- Request/approval directories separate roles; socket creation requires trusted
  ancestors and checked ownership/mode, rejects ambiguous/live replacements and
  reclaims only verified stale entries. Passed descriptors use CLOEXEC and bounded
  framing; unexpected/multiple descriptors are rejected.
- Privileged executor trusts broker UID, **not an independent PAM proof or cgroup
  check**. Broker/service-account compromise therefore crosses the execution boundary.
  It repeats strict command/path/argv checks, restricts executable paths to trusted
  root-owned directories/files, clears environment, runs direct argv, and durably
  claims the one-shot request ID before spawning. Root administrator updates to
  executables remain trusted; approval does not pin executable file contents.
- PAM passwords stay in the terminal conversation, not broker JSON. Local secret
  buffers are bounded and wiped; PAM-owned allocations/modules remain part of the
  credential-handling trust boundary. No real credentials were used in tests.
- Helper failure denies approval. Broker restart changes instance and discards
  pending state; executor replay journal is not queue/result persistence. Failure
  can leave execution outcome unknown and does not justify a retry/replay.

## 4. Packaging and R1

All candidate maintainer scripts were read from the exact artifact.

- Postinst checks name and numeric ID collisions in both directions and expected
  service primary GID/shell; fails with explicit repair guidance rather than deleting
  or renaming a conflicting identity. Compatible existing identities are reported
  and used as administrator-designated service/role identities, not proven package-owned.
- **R1 fixed:** legacy `mayi-pam-auth` is neither created, modified nor deleted by
  the new scripts. Matching name/UID/GID is not treated as ownership evidence.
- Removal/deconfiguration stops services; upgrade/error prerm branches do not delete
  identities. Purge removes package executor state/systemd registration but retains
  human accounts, service accounts and groups. Repeated configuration is idempotent
  under the tested conditions. Required broker role memberships may be added;
  preservation is not a claim that postinst never changes service group membership.
- Independently reproduced actual published 0.4.1 -> exact candidate upgrade with
  administrator-created `mayi-pam-auth` UID 23003/GID 23012: passwd record, shadow
  entry hash and socket-group record unchanged. Repeated configuration, name/UID
  and name/GID conflicts in both directions, explicit repair, removal and purge passed.
- Independently reproduced an actual failed production upgrade: wrong broker UID
  produced `install ok half-configured`, preserved records, and recovered to
  `install ok installed` after explicit UID repair/configuration. Reviewed/exercised
  old upgrade/unwind hooks preserved accounts. Both lifecycle harnesses exited zero.
- Published 0.4.1's own purge still deletes named accounts/groups; its PAM bypass
  also remains historical baseline behavior. The candidate cannot retroactively fix
  an old-package purge, rollback or continued old-version operation.

## 5. Independent test evidence

Two newly created Debian 12 QEMU overlays of the retained official base image;
KVM/q35, kernel 6.1.0-53-amd64, no host filesystem shares. Root qualification
harnesses were provisioned through cloud-init before Mayi installation, following
qualification's bootstrap workflow. No host privilege escalation or existing-guest
Mayi bypass was used. Synthetic approvers authenticated only through real installed
consoles/PTYS/PAM; random credentials stayed in guest memory and ECHO was checked off.

| Fresh installed-package case | Result |
| --- | --- |
| No PAM terminal descriptor | PAM_AUTH_REQUIRED; no authority |
| Locked password, no account expiry; unlock recovery | PASS |
| Initial NSS denial despite stale kernel supplementary role | PASS |
| Role removed while at real PAM prompt; final NSS denial | PASS |
| PAM socket unreachable with pending broker state; recovery | PASS |
| Real configured challenge expiration | PASS; 304.296 seconds total |
| Overlapping different-request success/failure; fresh auth recovery | PASS |
| Same-challenge overlapping authenticated decisions | One winner |
| Eight synchronized consumers | One execution, seven ALREADY_CONSUMED |
| Production upgrade/R1, collisions, removal/purge, failed upgrade recovery | PASS |

Expiry rejected console approval, fresh view, old-view replay and consumption with
no execution/revival. Concurrent consumption produced one broker transition,
one executor start and exactly one harmless guest-local marker line.

Reviewed existing Debian 11–13 raw results and used a separately written checker
(`verify-independent.py`) to cross-check locked status, isolation, consumer replies,
marker, journal event counts, real expiry and absence of expired execution in both
retained evidence and the fresh primary run. All checked cells passed. Existing
full 83+5 Rust results were reviewed, not rerun as a full matrix. Independently ran
33 retained broker unit tests and six Python packaging/isolation regressions, all
passing. Unit evidence is supplementary, not a substitute for installed PAM tests.

New raw transcripts, account records, journals, harness inputs, installed-payload
hashes, builder comparison, checker output and SHA256SUMS are retained in the
independent evidence directory. The two new QEMU processes and local HTTP fixture
server were stopped after collection; synthetic authentication accounts were absent
in primary cleanup. No existing VM or production service was stopped/restarted.
Initial QEMU daemonized+sandbox launches failed before boot; foreground backgrounded
launches succeeded, with no product/configuration workaround.

## 6. Limitations, remaining risks and publication recommendation

Non-blocking limitations, not newly confirmed candidate release defects:

- Broad human-approved root execution, including interpreters/shells; no semantic
  command safety, transaction rollback or child runtime deadline. Long-running
  children/serialized PAM sessions and finite workers/journal can impair availability.
- Resettable in-memory PAM throttle, privileged helper/PAM/NSS trust, fixed service
  identity and executor's broker-UID trust; no protection against root/TCB compromise.
- No queue/result persistence across broker restart; filesystem executor remains
  **DISCONNECTED / INCOMPLETE**. No Synology DSM or Debian 10 support.
- Only stock local Debian PAM qualified; third-party MFA/SSSD/custom modules and
  altered service/cgroup placement need separate qualification/security assessment.
- Metadata says libc6 >=2.28 although binaries need symbols through 2.30. This
  under-declaration should be corrected in future packaging, but supported Debian
  11–13 satisfy it; this verdict does not authorize installation on older platforms.
- No signed/reproducible build provenance claim; official image manifest checks
  do not establish detached-signature verification. The missing unpublished -5
  upgrade source was not substituted. Arbitrary dpkg unpack/I/O faults were not
  exhaustively injected. Old-version purge/rollback hazards remain as above.
- Correct boundary documentation's NSS-lock wording and distinguish broker zero
  effective capabilities from its unrestricted bounding set in follow-up work.

**Recommendation:** manually publish only the identified unchanged qualified bytes
through the project's TPA.run workflow, with immutable package/version/architecture
and independent repository-download hash verification. Publication is not deployment.
Nothing was staged or published during this audit; no candidate rebuild, production
change, filesystem enablement or privileged Docker test occurred.
