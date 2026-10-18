# Mayi 0.4.1-6 qualification status

## Status: READY FOR INDEPENDENT SECURITY REVIEW

The production upgrade **0.4.1 → 0.4.1-6**, all 21 diagnosed Rust failures,
and the four remaining installed-package integration gates now have passing
qualification evidence on Debian 11–13. Missing unpublished 0.4.1-5 bytes are
**not a production-upgrade failure**. This status authorizes neither publication
nor deployment and does not substitute for independent security review.

Exact unchanged candidate: `../mayi-qualification/artifacts/mayi_0.4.1-6_amd64.deb`

SHA-256: `dac2e40bbc073f991fb99ce382d97e1ae68bf50b3f1f6fb8f42bca1864e45d38`

No runtime or packaged files were modified during blocker resolution. No package
was rebuilt, staged, published or deployed; no production services were modified
and filesystem execution was not enabled.

## Evidence

Complete diagnosis, individual failure classifications, commands, guest details,
raw account records, original failures and corrected runs:
`../mayi-qualification/blocker-resolution/RESULTS.md` and
`failure-classification.json`. The previous report is preserved there as
`prior-release-report.md` rather than silently discarded.

Remaining installed-package integration gates, raw console/PAM/broker/executor
evidence, failed fixture attempts, independent evidence verification and cleanup:
`../mayi-qualification/remaining-integration/RESULTS.md` and
`verified-summary.json`. The pre-integration report is preserved there as
`prior-release-report.md`.

Final repeated-race/identity/expiry follow-up:
`../mayi-qualification/final-gates-supplement/RESULTS.md` and
`verified-summary.json`. This preserves and independently rechecks the earlier
integration evidence, with new raw results in `attempt2/debian11/` through
`attempt2/debian13/`. The prior release report is preserved in that directory.

## Production upgrade and R1 regression: PASS on Debian 11–13

Published production baseline 0.4.1 has SHA-256
`22409abd977d4d14113ee34e47ed78f94a4e975da84e9606f5fe704116f59ab0`, matching
`DEBIAN_COMPATIBILITY.md`. 0.4.1-5 was an unpublished candidate. Successful dpkg
upgrades execute the **new package's postinst**; therefore the matching-name/UID/GID
R1 scenario must primarily be tested against 0.4.1 → exact 0.4.1-6.

That actual upgrade passed on all three releases with the administrator-created
`mayi-pam-auth` account (UID 23003, GID 23012). Raw before/after passwd entries,
shadow-entry hashes, and socket-group records compare equal. Repeated postinst,
name/UID and name/GID collisions in both directions, explicit collision repair,
and removal/purge preservation passed. The complete lifecycle scripts exited zero.
Raw records are retained in `blocker-resolution/accounts11/`, `accounts12/`, and
`accounts13/`; these checks were repeated because the earlier temporary records
were lost at guest reboot, not because earlier successful results were ignored.

Separately, an actual 0.4.1 upgrade with a conflicting broker UID failed closed in
`install ok half-configured`, preserving account/group records; restoring the UID
and configuring recovered to `install ok installed` with all services active.
Old-version upgrade/error hooks were reviewed and separately exercised. Old
0.4.1 `prerm upgrade/failed-upgrade` does not delete accounts; `postrm` does not
perform its identity-deletion branch on upgrade/unwind arguments. **Old 0.4.1
purge does delete named accounts/groups**; that old-package hazard is not fixed
retroactively by a newer candidate. Direct hook tests are not exhaustive injected
dpkg unpack/I/O-failure coverage.

The exact original 0.4.1-5 artifact was not available and was not reconstructed.
Its additional upgrade regression remains unrun. No explicit current release
policy making every unpublished candidate a mandatory upgrade source was found;
the legacy container harness does enumerate historical artifacts as inputs, which
prevents running that harness unchanged without them but is not a production
upgrade requirement.

## All 21 Rust failures: classified and rerun

- **20 filesystem failures:** test-environment authority precondition missing.
  On ext4, `openat2(O_TMPFILE)` succeeds; subsequent `linkat(AT_EMPTY_PATH)` fails
  with **ENOENT (2)** without `CAP_DAC_READ_SEARCH` on Debian 11/12. Debian 13 permits the tested caller-owned inode publication without that capability. The implementation maps the failure
  to `O_TMPFILE_UNAVAILABLE`, obscuring the failing operation. Eighteen tests
  report that result directly; RSS and crash-recovery parents fail because their
  children hit the same syscall error before completing/reaching the crash point.
  Every affected test has a linked syscall trace in `failure-classification.json`.
- **1 stale-socket test:** nonportable inode-uniqueness assumption. ext4 reuses the
  just-unlinked inode, making `assert_ne(dev, ino)` fail despite successful unlink
  and rebind. The stale probe's ECONNREFUSED (111) is expected, not the defect.
  The unchanged test passes without capabilities on tmpfs. The fixture remains
  nonportable; a future independently reviewed inode-pinning fixture is preferable.

No unsafe filesystem fallback, disabled test, weakened assertion, or product
implementation change was needed. Filesystem fixtures remained on ext4 under
`/home/audit/.local/share/.mayi-fs-qual-*`. Only socket TMPDIR moved to private
`/dev/shm/mayi-test-tmp`. The non-root main test process received the single
`CAP_DAC_READ_SEARCH` capability inside the disposable guest. This does not claim
unprivileged filesystem support or authorize filesystem-executor enablement.

| Debian / kernel | Main Rust tests | Executor Rust tests |
| --- | --- | --- |
| 11 / 5.10.0-46-amd64 | 83 passed, 0 failed | 5 passed, 0 failed |
| 12 / 6.1.0-53-amd64 | 83 passed, 0 failed | 5 passed, 0 failed |
| 13 / 6.12.111+deb13-amd64 | 83 passed, 0 failed | 5 passed, 0 failed |

The passing runs had zero ignored/filtered tests. An additional Debian 13
capability-free run also passed 83 + 5 after correcting a harness TMPDIR mode
error (0775 caused three unsafe-ancestor rejections; the required mode is 0700).
These were the complete unchanged
Debian-11-built test binaries from the candidate source tree, run on each guest,
not candidate rebuilds. Runtime source/Cargo hashes match the current tree.
The disconnected-core qualification policy and negative no-capability controls
are documented in the detailed report. Local packaging/isolation regressions:
**6 passed**; `git diff --check` passed.

## Preserved earlier results and completed integration gates

Earlier exact-candidate Debian 11–13 installation, wrong/correct PAM password,
initial/final NSS checks, role restoration, missing-terminal rejection,
single-consumption/replay, concurrent proposal creation, helper outage/recovery,
service restart/cgroup/socket/identity checks remain valid. Broker capabilities
were zero; PAM helper was bounded to CAP_DAC_READ_SEARCH; both had NoNewPrivileges.

The four previously missing exact-candidate end-to-end gates are now qualified:

| Installed-package gate | Debian 11 | Debian 12 | Debian 13 |
| --- | --- | --- | --- |
| Locked-password PAM rejection and unlock recovery | PASS | PASS | PASS |
| Actual configured 300-second challenge expiration | PASS | PASS | PASS |
| Overlapping approval-console decisions and request isolation | PASS | PASS | PASS |
| Eight-way simultaneous one-shot consumption | PASS | PASS | PASS |

Disposable guest identities used random in-memory synthetic credentials and the
real installed console/PAM stack. Password locking left account expiration unset;
authentication failed, the request remained pending and consumption was rejected.
Unlocking restored normal authentication. Expiry tests waited real elapsed time
(approximately 304 seconds including collection/shutdown), rejected console
approval, fresh view retrieval, old-view replay and consumption, and showed no
execution or revival.

Overlapping consoles covered independent requests with correct/incorrect
passwords, fresh authentication after failure, and same-challenge competition
with one winner. The helper serializes PAM sessions; overlapping decisions do
not imply simultaneous PAM conversations. Cross-request/cross-UID view reuse
and wrong-digest negative controls were rejected. Eight synchronized consumers
produced one successful execution, seven ALREADY_CONSUMED rejections, one broker
transition, one executor start and exactly one guest-local marker line; later
retries were rejected. Filesystem execution remained disconnected.

Canonical evidence is in `remaining-integration/attempt4/` for gates 1/3/4 and
`attempt5/` for gate 2. Failed fixture attempts are preserved with actual
FAIL/SKIP outcomes and diagnoses (feedback parsing, removed Python spwd module,
serialized PAM, canonical executable path, console input timeout). Corrections
did not weaken authorization or alter product/PAM configuration. Synthetic
accounts were removed, services remained active, package verification was clean,
and guest/host artifact SHA-256 remained unchanged. The independent saved-evidence
checker passed all 12 gate/release cells. No implementation blocker was found
in this scope; the review concerns below remain applicable.

## Final repeated-race and identity supplement

All four final gates passed on Debian 11–13. Fresh disposable overlays of the
retained verified images were used after the former guests had shut down. Their
root fixture harnesses started before installing the unchanged candidate; no
installed Mayi privilege path was bypassed. Existing package-upgrade and Rust
matrices were not repeated.

- **Password locking and account expiration:** both independently rejected by
  the actual PAM stack; requests stayed pending/unconsumable. Password unlocking
  and clearing account expiration restored real authentication and execution.
  Password lock left account expiration unset; separate `chage -E 1` rejection
  is explicitly logged by PAM account management.
- **Real expiry:** new 300-second waits measured 304.842 / 304.657 / 304.968 seconds
  including collection. Expired approval, old-view replay and consumption were
  rejected without execution. Fresh challenges afterward succeeded without a
  broker/helper restart.
- **Concurrent identity isolation:** overlapping successful/failed authentications
  for two different requester UIDs did not cross-authorize requests. Wrong-owner
  consumption failed; the failed request needed fresh real authentication.
- **Repeated atomic consumption:** 20 barrier-synchronized races per release,
  alternating eight rightful owners and six rightful owners plus two wrong owners.
  Across the matrix: **480 attempts, exactly 60 executions**, 360 ALREADY_CONSUMED
  owner rejections and 60 UNAUTHORIZED_REQUESTER rejections. Each round had one
  marker line, one broker transition and one executor start. All 180 later replay
  attempts failed. Mixed challenge/digest substitution failed independently.
- All 23 regular installed payload files match the extracted candidate on every
  guest. Synthetic accounts and successful-run markers were removed; artifact
  hashes remained unchanged. Saved-evidence checks passed independently.

The first supplemental attempt exceeded the eight-worker capacity with ten
consumers and received connection resets, failing the harness's strict reply-code
expectation. Its FAIL logs remain preserved. The corrected run stayed within
capacity without weakening one-shot, ownership or observed-execution assertions.
This is a finite concurrency regression matrix, not proof over every schedule.

**Final decision: READY FOR INDEPENDENT SECURITY REVIEW.** No publication,
staging, deployment or filesystem-execution authorization is implied.

## Remaining concerns

Only stock local Debian PAM and supported amd64 Debian 11–13 are covered. Debian
10 remains unsupported. PAM helper privilege, exact systemd cgroup assumptions,
broad human-approved root execution, resettable in-memory throttling, unqualified
custom PAM, and published 0.4.1's separate PAM bypass remain review concerns.
At worker saturation, clients may receive connection resets rather than structured
protocol errors; the PAM helper also serializes sessions. These availability
limits must not be interpreted as authorization to retry an uncertain execution.
Queue/result persistence across broker restart is not claimed. Filesystem
execution remains **DISCONNECTED / INCOMPLETE**. Candidate binaries require
GLIBC symbols through 2.30 although package metadata says libc6 >= 2.28; this is
satisfied on supported Debian 11–13 but does not establish older-system support.
Official image HTTPS SHA-512 manifests were checked; detached signature
verification was not established. The rejected Debian-13-built candidate and all
prior artifacts remain unchanged.
