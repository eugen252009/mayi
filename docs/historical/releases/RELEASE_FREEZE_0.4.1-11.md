> Archive view: maintainer-local paths have been omitted. Commands containing
> `[local-only path omitted]` are historical records, not runnable instructions.
> Original bytes remain at the commit/path recorded by the documentation checker.

# Mayi 0.4.1-11 release-source freeze

Operator acceptance: “es passt” accepts the 0.4.1-11~ui2 interface only. No host installation/restart, source/release-tag/artifact/repository signing, central admission/staging, upload, publication or push is authorized.

Accepted package-input commit: 574a63dd05c70656e4014b363ae06afa75c1f273.
Accepted ui2 SHA256: 57a1f4d3aea949e7926db7d1e67898a2ec502713314a615171b76257d1ee7e12.
Parent documentation commit: dd948315b5e486cdef84aabc67ed3887f6e3396f (only reports changed from accepted package input).

The final source differs from that parent ONLY in authoritative executor/package/tpa.json version, the UX_USAGE heading and this freeze record. No Rust/Python code, dependency lock, unit, maintainer script, interface behavior, authorization policy or machine schema changes. Older reports in this source tree describe previous qualification cohorts, not final-version evidence or current host state.

Final-artifact qualification is separate: [local-only path omitted] The release bundle at [local-only path omitted] must contain its self-contained final reports and raw data before no-overwrite finalization. Until those gates pass this source freeze is NOT release approval. No historical package is renamed/repackaged as final.

Build identity: Debian11 amd64, Rust/Cargo1.95.0, GCC10.2.1, GLIBC2.31-13+deb11u14, locked offline Cargo dependencies, existing TPA tool SHA2564da9418be15d2d5e212e21ff399a33519ca342522633afaed6341705765370a7, SOURCE_DATE_EPOCH1792195200. Two clean builds and exact-package ABI/hardening, installed Debian11/12/13, PAM/PTY/UI, restart/expiry and60-race/480-attempt gates are mandatory.

No new signing authorization exists. This release commit is intentionally unsigned; cryptographic signing/admission prerequisites remain explicit for the central workflow. The trusted signed baseline ecc1ec6c4ccd5a33ee1f2b484b848f70fd642ee3 and pinned public fingerprint AF0C604F486726DFD4D2EF37D5888C81B647D648 establish ancestor verification, not a signature over this new commit. The exact final commit/archive/package/manifest hashes must be independently pinned for handoff.

Accepted scope remains30x8 or larger approval pages, explicit plain/scrollback fallback, conservative history and process uncertainty, consumption-time TTL, best-effort Journald, no automatic replay or general exactly-once effects, and DISCONNECTED / INCOMPLETE filesystem execution.
