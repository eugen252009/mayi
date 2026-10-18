# UI test results

Decision: **INCONCLUSIVE** for full UI release qualification. Implementation is a development candidate, not production-ready certification.

Executed locally, unprivileged:
- cargo test --offline -- --test-threads=1: **103 + 5 passed**, no skips (ui-evidence/rust-tests-final.log).
- Python prepared/final suite: **68 passed, 9 skipped**. Skips are pre-existing installed PAM console qualification tests; they are not PASS.
- cargo fmt --check: PASS after formatting changed Rust files.
- cargo clippy --offline --all-targets -- -D warnings: PASS.
- git diff --check: PASS.
- Offline debug build: PASS. Host lacks unversioned PAM linker name; used existing qualification test-link directory with RUSTFLAGS=-L native=... (actual host libpam). No installation or privilege escalation.
- ccc indexing attempted twice; timed out, no indexing success claimed.

New tests cover basename, invalid path, escaping/bidi/newlines, long argument pagination, compact/details, narrow data wrapping, deterministic spinner, rate limiting, redirects/dumb terminals, PTY output mode preservation. Rust input PTY test covers Space/brackets, approval/denial input frames, quit, Ctrl-C, repeated-frame rejection and invalid input bytes, with termios comparison. It does not grant real approvals. Existing tests cover decision parsing and broker state.

Initial Python attempt failed because cargo test had not built the standalone debug binary: six missing-binary failures; retained separately, followed by successful cargo build and rerun. Initial Rust compile failed due to one renderer test call site; corrected before passing runs.

Outstanding mandatory evidence: installed end-to-end authentication/approval/denial with synthetic PAM accounts in a disposable environment, full resize/disconnect/error lifecycle integration, deterministic timeout interaction integration, measured CPU usage during prolonged waits, and Debian package matrix. No real credentials or host PAM authentication exercised. Spinner exit tests test lifecycle mechanics, not all corresponding broker transitions. No package built.
