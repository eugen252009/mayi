# CONDITIONAL RESTART GO — package ready, installation pending

## Identity
Runtime source: ee22b0a278c2c9110d29bfc37bffcff09ec66bee.
Version: 0.4.1-10~status4 (greater than status3, less than final 0.4.1-10).
Artifact: dist/mayi_0.4.1-10~status4_amd64.deb.
SHA256: 6e785530c84cdf19eaac65419aa549f86290003d2e75c2642222218cba6c1d5e.

## Delivered
Reuse the random 192-bit broker identity as immutable epoch. New queued IDs are
versioned, fixed-width, domain-separated HMAC-SHA256 identities binding epoch,
128-bit random nonce and the canonical exact request digest. Only an owner-private
provenance key persists; requests/approvals/authority do not.

Authentic older IDs return BROKER_EPOCH_CHANGED with retryable=false and explicit
fresh-request/fresh-approval requirements, conservative execution UNKNOWN and
reconciliation required. Forged/unknown IDs do not become epoch errors.
Legacy history remains readable, without retroactive authentication.

Shutdown fences claims under the existing mutex and records only proven
pre-claim REQUEST_INVALIDATED cases. Crashes do not generate fictitious safe
outcomes. Old execution can survive broker death and later complete honestly.

History JSON2 adds epoch_id and separate authorization/execution/recovery fields.
Human boundaries are virtual, preserve display order and label first-page/legacy
context; --epoch filters recorded identities. No separator is persisted.
Live status schema1 is retained; status --preflight --json is read-only
READY=0/BUSY=3/UNKNOWN=4, never an admission or physical-idleness guarantee.
Porta recovery classes and package/self-upgrade response-loss semantics are
documented; no Porta code was changed.

## Qualification and conditionality
216 Python PASS / 9 historical skips; 143+13 Rust PASS; fmt, strict Clippy,
compileall and shell checks PASS. Two independent clean Debian11 builds are
byte-identical; max GLIBC_2.30 and mandatory package hardening/ABI gates PASS.

Debian11/12/13 each have 19/20 primary gates PASS and retained process exit1.
The classification fixture's rounded window included one genuine older
shutdown-invalidated request. A first retry incorrectly filtered unknown-epoch
diagnostics and remains FAIL. Separately instrumented/narrowed same-artifact
retry2 PASS/exit0 on every platform. Independent acceptance explicitly combines
original security evidence and retry2, not a fictitious all-green primary run.

CONDITIONAL rather than unconditional GO reflects those explicit evidence
qualifications, versioned-ID consumer migration and the requirement for external
coordination/reconciliation around updates. READY alone is not an update lock.
Review BROKER_EPOCH, RESTART_INVALIDATION, UPDATE_PREFLIGHT,
PORTA_RECOVERY_CONTRACT, EXECUTION_OUTCOME_SEMANTICS, RESTART_SECURITY_TESTS,
DEBIAN_MATRIX and SECURITY_REGRESSIONS before final release qualification.

## Preservation and limits
Host remains operator-installed 0.4.1-10~status3; dpkg -V passes.
Original dirty checkout and immutable releases/staging8/9 were not modified;
four pinned bundle manifests verified. No installation, service restart on the
host, Porta change, central staging change, signing, tag movement, upload,
publication, push or deployment. Candidate publication and deployment require
separate authorization.

Journald remains best effort. Proven old authorization invalidity is not proof
that execution failed or never occurred. No queue persistence, recovery of
capabilities, general exactly-once side effects or connected filesystem executor.
Private-key loss or unsafe storage fails classification/startup closed rather
than inventing stale identity proof. Historical outcomes remain historical.

Full evidence:
/home/eugen/projekte/mayi-qualification/restart-0.4.1-10-status4/
including check_results.py, independent-audit-final.json/.exit, original and
retry records, build logs, source.tar, package validation and preservation data.
