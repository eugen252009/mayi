# Filesystem test isolation

The direct filesystem core remains **DISCONNECTED / INCOMPLETE**. These checks
are test-harness regressions, not production filesystem or package qualification.

## Qualification environment policy (0.4.1-6 follow-up)

Disabled functionality is not grounds to ignore failed tests. Run the complete
suite in disposable guests, document syscall and authority prerequisites, retain
negative controls, and report failures rather than filter them out. Passing these
tests does not enable or qualify the filesystem executor for production.

On all tested kernels ext4 supports `O_TMPFILE` creation. Debian 11/12 require
`CAP_DAC_READ_SEARCH` for the tested `linkat(AT_EMPTY_PATH)` publication; without
it linking returns `ENOENT`. Debian 13's kernel allows publication of the tested
caller-owned anonymous inode without that capability (a separate complete
capability-free 83 + 5 run passed). The direct core labels linking failure
`O_TMPFILE_UNAVAILABLE`. Qualification runs use a non-root test UID with this
single effective/ambient capability **only in a disposable guest**; never grant
it to host tools or installed services for testing. Preserve a capability-free
probe verifying the per-kernel behavior: creation succeeds, linking fails closed
on Debian 11/12 but succeeds for the tested caller-owned inode on Debian 13. This is not evidence
of unprivileged filesystem-operation support.

Filesystem fixtures use HOME on ext4, not TMPDIR. The broker stale-socket test
assumes a newly bound socket has a different inode after unlink; ext4 can legally
reuse that inode immediately. Keep socket TMPDIR in a private tmpfs directory
for the unchanged suite. This is a documented nonportable fixture assumption,
not a production filesystem restriction or permission to weaken an assertion.
A future fixture correction should pin the old inode while testing replacement.

The complete unchanged candidate-source test binaries passed 83 + 5 tests on
each of Debian 11–13 under these conditions. Exact failures, syscall traces,
capability controls, mount details and all logs are retained under
`/home/eugen/projekte/mayi-qualification/blocker-resolution/`. Original failure
logs remain preserved. See `RELEASE_REPORT_0.4.1-6.md` for separate package/runtime
readiness gates; unit-suite success alone is insufficient.

## Why the tests serialize

Filesystem unit tests use temporary, process-specific directories under
`~/.local/share/.mayi-fs-qual-*`. They do not share the installed broker or
privileged executor's service locks.

A subprocess started by another thread inherits open file descriptions until
successful `exec`, even when the descriptors have `O_CLOEXEC`. This can retain a
fixture's `flock` after its parent context is dropped. Tests immediately reopening
the fixture can then receive `EXECUTOR_ROOT_BUSY`. Failed executable-path lookup
attempts prolong this window.

This was reproduced intermittently in the parallel suite and with `strace`
delaying `execve` entry by 100 ms. The latter reproduced both
`delete_and_move_recheck_content_and_identity_before_commit` and
`interrupted_stage_cleanup_is_reported_by_artifact_and_reaped_on_restart`.

## Harness rule

Every test in `executor/src/filesystem.rs` takes the process-local
`TEST_ISOLATION` mutex before doing any work. The guard covers the complete test,
including fixture teardown and subprocess waits. Child helpers run in fresh
processes and use independent mutexes. Fixture-level locking is unsuitable because
one test may create multiple fixtures.

Internal race threads remain concurrent. Production `flock`, nonblocking failure
behavior, and descriptor handling are unchanged; no sleeps or retries mask the
failure. Other unit-test modules currently do not spawn child processes while
these tests run. If such subprocess tests are introduced, extend the isolation
boundary or move the filesystem tests to a separate test process.

`tests/test_filesystem_test_isolation.py` ensures newly added filesystem unit
tests also acquire the guard first.

## Verification

- Default Cargo test run: 77 main/broker/filesystem tests and 5 privileged-executor
  unit tests passed.
- Three additional main test-binary runs with `--test-threads=32`: all passed.
- The same 100 ms exec-entry-delay reproduction: 73 passed, four stress tests
  filtered; both previously failing tests passed.
- Python: 52 passed, nine PAM/package console tests explicitly skipped.
- Formatting, Clippy (`--all-targets -- -D warnings`), and diff checks passed.

The installed Mayi services remained running and were not restarted. The skipped
console/package checks still require separate release qualification.
