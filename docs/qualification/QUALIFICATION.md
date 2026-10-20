# Qualification and release identities

## Current qualified release: 0.4.1-11

- Source commit c5477fb19e1b979be980b451b6242e3565c9425a (UNSIGNED).
- Post-release stable-status ancestor 3b6b6127c6af682e3f7894dd1b98bac31a04a2e3.
  Consolidation adds documentation only; it does not qualify a newly built package.
- The qualified release bundle is not included in this repository; no public
  download location is established here.
- Package artifacts/mayi_0.4.1-11_amd64.deb:
  SHA-256: 5499b09620b91ba4770d402e054600117a52a98448cc0d486b7f3d1fe6a3b899.
- Source source/mayi-0.4.1-11.tar.gz:
  SHA-256: f9ed636fbb49b99acab3f5fb034b0823b07aa465a0a079edc0e1b1a3f33273f4.
- SHA256SUMS digest:
  4ee91e3b78bcf33d306c56ada8992f31e0d68060e6cf98c9c21a9c9b2db75722.

Raw final qualification evidence, push receipts, consolidation inventories and
private preservation archives are not included in this repository. The results
below are recorded summaries, not independently reproducible evidence supplied
by this checkout. Original evidence remains preserved outside the source tree;
no private logs or large release artifacts have been imported.

## TESTED scope, not universal proof

Debian 11/12/13 amd64 each passed 44/44 final installed gates and separate 3/3 full package/
CLI supplement PASS (exit 0). Source tests: 242 Python and 146 + 13 Rust passes; nine explicit historical
source-console skips separately covered by installed real PAM/PTY qualification.
Actual six-size review/denial/notices, account/session/PAM/abnormal terminal recovery,
exact argv/owner/digest/replay, native audit/history/status/preflight, epoch/restart
residual work, real 300-second consumption expiry and package lifecycle were tested.
60 races/480 attempts/60 authorized consumptions/60 independent markers/zero
duplicates. Two clean Debian 11 builds byte-identical; ABI/hardening PASS, maximum
required GLIBC 2.30 <= declared 2.31. 2,987 manifested files; 12 corruption-negative
copies rejected; independent offline verification PASS.

The primary suite and separate supplements remain separate. Two supplement setup
failures, review/auditor corrections, ui1 NO-GO and original ui2 overlap-fixture
failures/retries are retained, never called earlier successes. Operator “es passt”
is interface acceptance, not automated evidence or host installation permission.
No new final-version host test is invented by source consolidation.

The public fingerprint AF0C604F486726DFD4D2EF37D5888C81B647D648 verifies trusted
signed ancestor ecc1ec6c4ccd5a33ee1f2b484b848f70fd642ee3, NOT a signature on the
unsigned final commit. Independently pin final hashes. Central attestation/tag/
artifact/APT signing and admission/staging/publication remain separate prerequisites;
no action in this task changes those states. No source re-signing/history rewrite.

## Historical evidence

Original/staged 0.4.1-8,0.4.1-9,0.4.1-10 and original 0.4.1-11 remain immutable.
See [historical index](../historical/INDEX.md) for versioned source-era reports/research.
Current contracts/tests are not retired merely because introduced before 0.4.1-11.
Earlier package ABI failures or partial platform passes do not substitute for
final-artifact evidence. Existing release manifests/provenance are authoritative
for their own identities; no “fully secure”, general exactly-once, durable journal,
queue recovery or new-platform claim follows. See [limitations](../security/LIMITATIONS.md).
