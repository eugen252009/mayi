# Development, build and release

Use a checkout of this repository's **main** branch in any working directory.
Its self-contained Git repository has independent object storage,
no alternates or external common-dir dependency. GitHub's default main contains
the same consolidated application, documentation and manpages. Create future work
from canonical main or an explicitly qualified successor.

The older shared repository and all nine original worktrees remain preserved;
[historical index](../historical/INDEX.md) records their roles.
Do NOT delete/clean/reset existing historical worktrees or import unknown experiments. They
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
- [package scripts](../../executor/package/DEBIAN), [units](../../executor/package/usr/lib/systemd/system)
  and [PAM config](../../executor/package/etc/pam.d/mayi-approve) own installed identities,
  paths/lifecycle. Do not infer them from an outdated release report.
- [build-deb.sh](../../executor/package/build-deb.sh) derives root from its own location,
  creates fresh native targets, writes the build stamp, copies the 21 topic-owned
  detail documents with their relative layout, applies deterministic timestamps
  and the ABI gate. Only documentation source/install paths changed; authorization,
  executable payload, dependency and lifecycle definitions did not.

## Documentation packaging paths

[The complete 22-file migration map](ROOT_DOCUMENTATION_MAP.md) records source paths,
installed destinations and pinned original views. The 21 package documents were
an explicit shell list, not a TPA/Debian requirement for root placement. They now
install under /usr/share/doc/mayi/{architecture,security,user}/ with the same
basenames/set and 0644 modes. This preserves their relative cross-topic links.
The two manuals remain in their established man1/man7 locations; mayi(1)'s three
document references follow the new installed paths. Copyright/lifecycle/TPA
configuration are unchanged. The security policy lives at docs/SECURITY.md,
a GitHub-supported discovery location, and was not a Debian input.

Root Markdown is exactly README.md, PROJECT_STATUS.md and AGENTS.md; no aliases,
uppercase extensions or Markdown symlinks hide other root documents. Future
path migrations must check every intended package document and installed link,
not just a successful shell exit. Documentation-input changes can change .deb
bytes; validate distinct disposable development identities in isolated copies,
never rebuild/replace 0.4.1-11 or commit a version solely for documentation.
Root-cleanup raw evidence is not included in this repository and is not a
prerequisite for the documentation checker below.

## Fresh checkout setup

These steps prepare an unprivileged source-development environment, not an
installed privileged Mayi service. Use a disposable Linux environment for tests.
Do not replace a working system installation with a development build.

Prerequisites:
- Git and Python **3.11 or newer**, with venv/pip support, as required by
  [pyproject.toml](../../pyproject.toml). The development Python requirement is
  distinct from the qualified Debian package runtime scope.
- Rust/Cargo with rustfmt and Clippy. The recorded qualification used Rust/Cargo
  **1.95.0**; this repository does not declare a tested minimum Rust version.
- A C compiler/linker and PAM headers/link library (Debian packages
  `build-essential` and `libpam0g-dev`). Provision these through your environment's
  authorized administration workflow, not by granting tests host capabilities.
- Network access for the initial Python and Cargo dependency downloads.

```sh
git clone https://github.com/eugen252009/mayi.git
cd mayi
python3 --version
cargo --version
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e '.[test]'
cargo fetch --manifest-path executor/Cargo.toml --locked
```

Use a full clone: the documentation checker reads original historical Git
objects. A source ZIP or shallow clone is insufficient for that check.
The editable Python install creates development entry points inside the venv;
it does not install system services, create approval roles or configure PAM.
Leave the venv before using an existing system installation.

Only after `cargo fetch` succeeds for the selected platform/toolchain should the
offline commands below be used. A fresh clone alone contains no Cargo download
cache. Python test dependencies are also not vendored or fully pinned here.
These steps describe development setup, not an exact release reproduction.

## Local tests, not production qualification

Documentation-only navigation checks use [check_documentation.py](check_documentation.py):
`python3 docs/development/check_documentation.py --json /tmp/mayi-doc-check.json`.
It checks local GitHub-style links/anchors, pinned historical bodies, index/source
coverage and rationale references using the standard library and existing full
Git history. It never imports the application or contacts production services;
external URL availability and technical prose still require review.
Run documentation regression tests with
`python3 -m unittest discover -s docs/development -p 'test_*.py'`.
Neither documentation command requires installing the application.

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
PAM link development prerequisites (on Debian, the libpam0g-dev package).
The original qualification host used a host-specific test-link alias; that alias
is not provided here and must not be assumed to exist on another machine.
See [test isolation](TEST_ISOLATION.md) for disabled filesystem fixture/kernel
conditions; do not grant host capabilities for tests. Existing tests remain
discoverable, including experimental-core regressions. Console skips in the
source suite require separate disposable installed real-PAM evidence, not relabelled
passes. No service/installed-package testing is authorized by a docs migration.

## Reproduction and release boundaries

The qualified build environment is Debian 11 amd64, Rust/Cargo 1.95.0, GCC 10.2.1,
GLIBC 2.31-13+deb11u14, locked offline Cargo, SOURCE_DATE_EPOCH=1792195200 and exact
TPA tool SHA-256: 4da9418be15d2d5e212e21ff399a33519ca342522633afaed6341705765370a7.
The original qualification used a separate immutable bundle containing source,
Cargo cache/index, the exact TPA tool and build instructions. That bundle and its
assembly tooling are not supplied by this checkout. The environment description
above is historical provenance, not a complete reproduction recipe. Do not infer
that a fresh clone can reproduce the released package offline.

For a FUTURE independently authorized release, build two clean roots/outputs,
limit parallelism (recorded builds use 4 jobs), require cmp/hash equality, exact
ABI/dependency/PIE/RELRO/NOW/NX gate and no GLIBC requirement newer than 2.31;
qualify relevant installed Debian/PAM/terminal/security/restart/concurrency gates.
The builder requires an independently obtained TPA executable supporting `json`
and `build`; it uses `TPA_BIN` or `tpa` on PATH. The source repository is
[TPA](https://github.com/eugen252009/tpa). A current TPA build is not automatically
the historical qualified tool. See the checked-in [builder](../../executor/package/build-deb.sh)
for its inputs and [ABI checker](../../executor/package/verify_abi.py) for artifact checks.
A future release needs a reviewed build procedure and distinct approved version;
this document does not provide an automated publication recipe.
Do NOT run it to regenerate/overwrite 0.4.1-11 merely for documentation changes.
Verify an existing package read-only with:
```sh
python3 executor/package/verify_abi.py --json /path/to/exact-qualified.deb
```

For a future release, preserve source and artifact hashes, failed attempts, skips
and exact-environment evidence. Bundle assembly, offline/negative verification and
no-overwrite finalization require a separately reviewed, available release procedure.
That procedure is not included here: stop at source checks unless it is supplied
and release work is explicitly authorized. The [qualification summary](../qualification/QUALIFICATION.md)
records historical results and identities, not executable assembly instructions.

Central workflow exclusively owns subsequent admission/staging, source attestation,
release-tag/artifact/APT signing, immutable upload/publication and independent APT
consumer verification. Publication is not deployment. No signing/push/install/
restart or infrastructure work is implicit in a source/docs task.

## Change discipline

STABLE — SECURITY MAINTENANCE: the intended feature set is complete and the focus
is reactive security fixes. Broader work needs a separate explicit decision;
see [project policy](../../PROJECT_STATUS.md). Define acceptance criteria, inspect
code/contracts, make the smallest
change, add focused regressions, run affected checks and qualify exact artifacts.
Invariant changes require explicit review. Update the ONE owning current document;
link rather than repeat. Preserve historical originals and evidence scope.
No blanket staging, destructive reset/clean, credential import or automatic push.
