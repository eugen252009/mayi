# Development, build and release

Canonical working directory: /home/eugen/projekte/mayi/, checked out on **main**.
Its self-contained /home/eugen/projekte/mayi/.git has independent object storage,
no alternates or external common-dir dependency. GitHub's default main contains
the same consolidated application, documentation and manpages. Create future work
from canonical main or an explicitly qualified successor.

The older shared repository and all nine original worktrees remain preserved;
[historical index](../historical/INDEX.md) records their roles. The former linked
canonical checkout is retained at /home/eugen/projekte/mayi-preserved-consolidated-worktree/.
The original dirty checkout/shared .git remains at
/home/eugen/projekte/mayi-preserved-original-consolidation/.
Do NOT delete/clean/reset those directories or import unknown experiments. They
are historical/unfinished work, not dependencies of the standalone canonical
repository. Do not infer authority from Git's administrative main-worktree label.

## Source and configuration authority

- Python CLI/client/history/status: mayi/. Rust broker/PAM/UI/executor: executor/src/.
- [tpa.json](../../executor/package/tpa.json) control.version is the release identity.
  [version.py](../../mayi/version.py) uses it at build/source time and the installed
  _build_version stamp at runtime. pyproject/Cargo component versions are not
  Debian product versions.
- [Cargo.toml](../../executor/Cargo.toml) plus [Cargo.lock](../../executor/Cargo.lock)
  define locked Rust dependencies. TPA Depends defines installed runtime packages.
- [package scripts](../../executor/package/DEBIAN/), [units](../../executor/package/usr/lib/systemd/system/)
  and [PAM config](../../executor/package/etc/pam.d/mayi-approve) own installed identities,
  paths/lifecycle. Do not infer them from an outdated release report.
- [build-deb.sh](../../executor/package/build-deb.sh) derives root from its own location,
  creates fresh native targets, writes the build stamp, copies existing root
  detail documents, applies deterministic timestamps and the ABI gate.
  Packaging code/layout is unchanged by this consolidation.

## Local tests, not production qualification

Documentation-only navigation checks use [check_documentation.py](check_documentation.py):
`python3 docs/development/check_documentation.py --json /tmp/mayi-doc-check.json`.
It checks local GitHub-style links/anchors, pinned historical bodies, index/source
coverage and rationale references using the standard library and existing full
Git history. It never imports the application or contacts production services;
external URL availability and technical prose still require review.

```sh
cargo build --manifest-path executor/Cargo.toml --locked --offline
python3 -m pytest -q -rs
cargo test --manifest-path executor/Cargo.toml --locked --offline -- --test-threads=1
cargo fmt --manifest-path executor/Cargo.toml -- --check
cargo clippy --manifest-path executor/Cargo.toml --locked --offline --all-targets -- -D warnings
python3 mayi/version.py
sh -n executor/package/build-deb.sh
```
Build standalone debug binary BEFORE Python tests that invoke it. Rust requires
PAM link development prerequisites; on this qualification host the recorded
RUSTFLAGS=-L native=/home/eugen/projekte/mayi-qualification/final-signoff-0.4.1-8/test-link
provides the existing test-link input, not a new production-library choice.
See [test isolation](TEST_ISOLATION.md) for disabled filesystem fixture/kernel
conditions; do not grant host capabilities for tests. Existing tests remain
discoverable, including experimental-core regressions. Console skips in the
source suite require separate disposable installed real-PAM evidence, not relabelled
passes. No service/installed-package testing is authorized by a docs migration.

## Reproduction and release boundaries

The qualified build environment is Debian11 amd64, Rust/Cargo1.95.0, GCC10.2.1,
GLIBC2.31-13+deb11u14, locked offline Cargo, SOURCE_DATE_EPOCH1792195200 and exact
TPA tool SHA2564da9418be15d2d5e212e21ff399a33519ca342522633afaed6341705765370a7.
Full prerequisites/instructions are in the immutable bundle BUILD.md. That bundle
ships source, lock/cache/index and tool, NOT an OS/compiler bootstrap.
Offline verification is not proof of arbitrary bare-host offline reproduction.

For a FUTURE independently authorized release, build two clean roots/outputs,
limit parallelism (recorded builds use4 jobs), require cmp/hash equality, exact
ABI/dependency/PIE/RELRO/NOW/NX gate and no GLIBC requirement newer than2.31;
qualify relevant installed Debian/PAM/terminal/security/restart/concurrency gates.
Package builder command is TPA_BIN=/qualified/copied/tpa CARGO_NET_OFFLINE=true
CARGO_BUILD_JOBS=4 SOURCE_DATE_EPOCH=1792195200 sh executor/package/build-deb.sh /fresh/output.
Do NOT run it to regenerate/overwrite0.4.1-11 merely for documentation changes.
Verify an existing package read-only with:
```sh
python3 executor/package/verify_abi.py --json /path/to/exact-qualified.deb
```

Freeze auditable source first; preserve exact identities/failed attempts/skips,
assemble a self-contained mayi-release-bundle/1 at ~/projekte/releases/mayi/<version>/
in an incomplete same-filesystem directory, verify offline/negative copies,
finalize with existing fsync/RENAME_NOREPLACE convention. Receipt stays outside.
Do not invent new competing bundle tools in source: use reviewed qualification
assembly records indexed in [qualification](../qualification/QUALIFICATION.md).

Central workflow exclusively owns subsequent admission/staging, source attestation,
release-tag/artifact/APT signing, immutable upload/publication and independent APT
consumer verification. Publication is not deployment. No signing/push/install/
restart or infrastructure work is implicit in a source/docs task.

## Change discipline

STABLE — ACTIVELY MAINTAINED: concrete security/correctness/compatibility/usability/
measured performance needs and useful new features remain welcome, not a permanent
freeze. Define acceptance criteria, inspect code/contracts, make the smallest
change, add focused regressions, run affected checks and qualify exact artifacts.
Invariant changes require explicit review. Update the ONE owning current document;
link rather than repeat. Preserve historical originals and evidence scope.
No blanket staging, destructive reset/clean, credential import or automatic push.
