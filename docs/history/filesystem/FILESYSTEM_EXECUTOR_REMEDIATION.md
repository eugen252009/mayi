# Historical filesystem-executor qualification record — INCOMPLETE

> Archived engineering evidence, not current user documentation. The current product status is summarized in [`../../FILESYSTEM_EXECUTOR_STATUS.md`](../../FILESYSTEM_EXECUTOR_STATUS.md). This record describes the historical qualification snapshot, not the current Git working tree.

## Decision and preserved boundary

**Do not integrate or enable the filesystem executor.** New qualification closes several prior gaps (private bind-mount tests, real ext4 ACL/capability fixtures, concurrent race stress, RSS sampling), but the syscall failure matrix is still partial, cleanup failure is not reported structurally, and device-node/LSM-label gates are unavailable. Independent security audit remains required.

- Qualification snapshot base/HEAD: `a593e6920551b52e9eef4565e1752c1c8f6593e6`; that historical snapshot was uncommitted/dirty.
- The Protocol 5 broker now has a separate exact-command MVP path. Structured filesystem operations remain disconnected and their consume path returns `CONSUMED / EXECUTION_DISABLED`; no production caller reaches `ExecutionContext::execute`. The retired protocol-v4 socket service fails before bind.
- Core: direct test-only qualification path; disconnected from broker. EUID 0 is refused by `ExecutionContext::open`. No real-root or live fake-root execution was enabled.
- Qualified support: **ext4 only**. Runtime admission combines ext superblock magic with the filesystem type for the pinned mount ID in `/proc/self/mountinfo`; a disposable tmpfs mount was observed and rejected by the admission function. No broader filesystem claim.
- The filesystem test fixtures were under `$HOME/.local/share` on `/dev/nvme0n1p1`, mount `/`, type ext4. Bind and tmpfs mounts were created only in a child `unshare -Urnm` user+mount namespace; that namespace disappeared with the child. The host mount namespace was not changed.

## Direct API trust review

`ExecutionContext::open(root, requester_uid)` takes a caller-selected root path and caller-supplied numeric UID. The UID is only compared with `geteuid()`; the core cannot prove it came from `SO_PEERCRED`. `FsOperation` is directly constructible. The API is private at the crate-module boundary and has no broker caller, but any future internal caller could supply a fictitious requester UID or choose a weaker root. This is test/execution context, **not authenticated identity or authorization**.

Future integration must require a broker-created, immutable authorized request bound to the requester UID authenticated by `SO_PEERCRED`, plus a trusted execution context/root from deployment configuration. Conceptually require `AuthenticatedAuthorizedFilesystemRequest`, not raw operation + caller-supplied UID. Do not implement that handoff in this milestone.

## Syscall/failure map

No `fchown`, `ftruncate`, `pread`, `pwrite`, `fdatasync`, or `fgetxattr` call is used. `File::set_permissions` applies mode with a file-descriptor permission syscall; `write_all`, `read`, `sync_all`, `File::open`, and descriptor drops use Rust std wrappers. Failure points generally return before the corresponding syscall; they are **not** syscall-result injection. Actual EIO/ENOSPC/EDQUOT/EROFS and kernel-generated EINTR coverage remains absent.

| Call/path | Before commit failure meaning | After namespace mutation meaning | Cleanup | Injection/live evidence |
|---|---|---|---|---|
| `openat2` (pin root, resolve parent/target, staging/recovery) | Reject/no commit | Not used after commit | Owned FDs drop | Invalid/symlink/magic-link/no-xdev cases live; injected per-syscall errno: **no** |
| `open` / `File::open` (root ancestry, `/dev/urandom`, mountinfo) | Reject/no commit | Not used | RAII close | Live normal opens; open error injection: **no** |
| `fstat`, `fstatat`, `fstatfs`, `statx` | Reject/no commit | Post-commit identity checks can become uncertain | FDs drop | Real metadata/type/mount-ID checks; syscall failures not injected |
| `read` / `read_exact` / `read_to_end` | `READ_FAILED`/validation failure, no commit | Not used | buffers and cloned FD drop | Base-read failpoint before read; live bounded reads; EINTR/read error not injected |
| `write_all` to anonymous stage | `WRITE_FAILED`, no namespace commit | Not used after namespace commit | Anonymous FD drop; no pathname | Partial-write failpoint and normal short-write loop; actual short write/EIO/ENOSPC not forced |
| O_TMPFILE creation (`openat2`) | Reject/no commit | Not used | Anonymous inode dies on last close | Live on ext4 for Patch/Create; creation error not injected |
| mode application (`File::set_permissions`) | Reject/no commit | Not used after commit | FD drop | before/during/after metadata test points; actual fchmod failure not injected |
| `flistxattr` (size + list) / `FS_IOC_GETFLAGS` | Reject/no commit | Not used | buffers/FD drop | Ordinary xattr, ACL, and capability rejection live; syscall errors not injected |
| staged `fsync` (`sync_all`) | Reject/no commit | Not used after commit | Anonymous FD closes | before/during/after failpoints; successful ext4 calls live; actual EIO/ENOSPC not injected |
| `linkat(AT_EMPTY_PATH)` (FileCreate final name; Patch stage name) | Collision/failure should leave no final approved mutation | If syscall outcome is ambiguous, identity check returns uncertain | Patch stage `unlinkat`; Create has no named temp | Real EEXIST collision and success live; EINTR branch source-reviewed only; other errors not forced |
| `renameat2(RENAME_NOREPLACE)` (Patch replace / Move) | Collision/failure should leave old namespace | Ambiguous result maps to uncertain | Patch staging name cleanup | Live success and no-replace collision; injected pre-syscall failure; non-EINTR errors not forced |
| `unlinkat` (Delete and staging/recovery cleanup) | Delete failure should leave target | Successful unlink followed by fsync failure is uncertain | Stage cleanup attempted | Delete pre-syscall injection; cleanup failure injected in Drop; actual unlink EIO/EROFS not forced |
| parent `fsync` (all namespace mutations; both parents for cross-dir Move) | Not applicable before commit | Failure maps to `CommittedDurabilityUncertain` | FDs close | Failure points and committed namespace inspected; real ext4 fsync success exercised; actual fsync error not injected |
| `flock`, `fdopendir`, `readdir`, `closedir`, `close`/OwnedFd drop | Root lock/recovery fails closed where observed | Not part of commit | RAII/closedir; close result ignored | lock behavior and FD counts tested; close/readdir syscall failures not injected |

**Outcome caveat:** `ExecutionOutcome` is an enum (`NotCommitted`, `Committed`, `CommittedDurabilityUncertain`), so the commit truth is not flattened to a generic error. However, `StagedName::drop` ignores cleanup errors. A test injects cleanup failure and observes `NotCommitted` with old target bytes and a remaining reserved staging name; startup recovery later reaps it. The caller does **not** receive a separate `cleanup_status`. Thus commit truth remains correct in the demonstrated precommit case, but cleanup status is hidden. There is no postcommit staging cleanup: the stage is disarmed after replacement; anonymous descriptors are RAII-released. This is not the requested complete structural cleanup outcome model.

No `NOT_COMMITTED` result has been observed after an injected post-commit directory-fsync failure; actual bytes/names showed the committed result. Nevertheless, generic kernel errors from `linkat`, `renameat2`, and `unlinkat` have not been injected, and the full post-error namespace classification matrix is unproven. Do not claim “every syscall failure path accounted for” or full EIO safety.

## Bind mounts and filesystem admission

`bind_mounts_are_live_rejected_in_private_mount_namespace` uses a child `unshare -Urnm` test helper to make (1) a directory bind at `root/a/b` and (2) a file bind directly over `root/a/target-file`. Core `openat2` resolution flags return `MOUNT_CROSSING` for both. The helper never constructs `ExecutionContext` because its namespace-root EUID is intentionally refused; this is live kernel/flag-path evidence, not an end-to-end executor-context test. A private tmpfs mount was also rejected by `ensure_supported_fs`.

Hostile mount-namespace changes are not claimed safe. Deployment must prevent requester access to the executor's mount namespace; future privileged integration needs a trusted/private mount topology. No host mounts were created.

## Concurrent race stress

A new barrier/channel-coordinated second thread mutates the namespace while the executor is paused immediately before its final revalidation/commit:

- FilePatch same-inode content change: **10,000** attempts; all `TARGET_CHANGED`, racer bytes retained.
- FileMove destination creation: **10,000** attempts; all `MOVE_CONFLICT`, source bytes retained, racer destination retained.

The test took about 30 seconds on this host. Existing deterministic interleavings remain: FilePatch pathname replacement 100; FileDelete same-inode change and pathname replacement 100 each; FileMove source same-inode change and pathname replacement 100 each; FileMove destination creation 1,000; symlink swaps 100; hardlink insertion 100; staging substitutions 50 regular + 50 symlink; parent-component movement 100 plus one move-outside-root case. These remaining classes are not all 10,000-iteration concurrent stress. No unauthorized successful transition was observed in tested races.

## Stall, ACL, capability, label, and device evidence

- **FIFO and Unix socket:** Patch/Create/Delete/Move target/source paths are attempted; special-file resolution rejects before content I/O, and each case is asserted under one second. FIFO is opened nonblocking if reached. This is a finite regression, not a guarantee against stalled regular filesystem syscalls.
- **Deadline:** configured `MAX_OPERATION_DURATION` is 10 seconds. An injected expiry before commit returns `NotCommitted`; no actual stalled kernel syscall, FUSE stall, blocked device, or post-commit deadline was tested. There is no syscall cancellation. “Filesystem operations cannot block indefinitely” is **not established**.
- **ACL:** live ext4 POSIX ACL created with `setfacl` on a target; FilePatch/Delete/Move all returned `UNSUPPORTED_METADATA`, with original bytes/path retained. ACL-bearing ancestry was created and FilePatch failed closed (`UNTRUSTED_TOPOLOGY`). The fixture tool was available; no production dependency was added.
- **File capability:** a disposable file received a real `security.capability` xattr from a short-lived user-namespace fixture-construction helper (namespace root maps to the unprivileged host test UID). The file was never executed. The actual Mayi test process remained host UID 1000 without added capabilities; after the xattr was created, FilePatch/Delete/Move each returned `UNSUPPORTED_METADATA`. The helper did not invoke `ExecutionContext` while namespace EUID was 0.
- **LSM labels:** SELinux filesystem absent; no live SELinux/SMACK label could be created. Generic xattr rejection is source-reviewed, not equivalent to a live label test. Evidence: **SOURCE REVIEW ONLY / NOT LIVE TESTED**.
- **Character/block nodes:** `mknod c 1:3` was attempted only in a disposable ext4 fixture and in a private user/mount namespace; both attempts were denied (`EPERM`). No device node was opened and no host block device touched. Device-node handling is **NOT LIVE TESTED**; rejection is source-review only.

## RSS and other resource bounds

An isolated subprocess measured `/proc/self/status` while running eight accepted maximum-size (16 MiB) FilePatch results, one successful 1,024-edit patch, 1,000 malformed operations, and eight maximum-file hash-mismatch rejections. The final run reported:

```text
RSS baseline: 3,540 KiB
RSS peak (VmHWM): 85,900 KiB
RSS final (VmRSS): 69,536 KiB
maximum-result RSS samples: 69,536 KiB × 8
```

The allocator retained roughly 66 MiB over baseline after the stress but samples did not continue rising over those eight iterations; this is bounded observed allocator/runtime retention, not a universal RSS bound or long-duration leak proof. An explicit test budget rejects >128 MiB growth for this workload. FD stress remains 10,000 rejected operations, isolated serial measurement baseline/peak/final **9/9/9**, one pinned root FD. Existing boundary tests cover limit−1/limit/limit+1 for file/result, patch size/count, and logical path length; max-result content hash and max-edit result hash are checked.

## Filesystem operations / primitive evidence

- ext4 O_TMPFILE staging for FilePatch and FileCreate: **LIVE TESTED**.
- FileCreate no-replace link and FileMove `RENAME_NOREPLACE`, including a destination created before commit: **LIVE TESTED**.
- FilePatch/Create/Delete/Move successful ext4 operations and namespace outcomes: **LIVE TESTED**.
- Parent directory fsync success and injected failures, including both parents for cross-directory Move: **LIVE TESTED + DETERMINISTIC FAILURE INJECTION**; injected errors are simulated around, not returned by the kernel syscall.
- Power-loss/reboot/storage-cache durability: **NOT TESTED / NOT CLAIMED**.
- Non-ext4 runtime rejection: tmpfs `ensure_supported_fs` path **LIVE TESTED** in private namespace; XFS/Btrfs/overlayfs unavailable and not claimed.

## Release and frozen-plane safety

Test-only failure/race/crash hooks are under `#[cfg(test)]`; latest release binary string scan found no test-point, crash-environment, or pause-marker strings. Cargo has no normal feature enabling these hooks. The broker has no production call to `ExecutionContext::execute`; direct UID is not authentication.

## Results and remaining mandatory blockers

- `cargo test --manifest-path executor/Cargo.toml --locked`: **62 passed**.
- `python3 -m pytest -q`: **56 passed**.
- Clippy all targets/all features with `-D warnings`: **passed**.
- `cargo fmt --manifest-path executor/Cargo.toml -- --check`: **passed**.
- `git diff --check`: **passed**.
- Isolated FD stress: **10,000** rejected operations, baseline/peak/final **9/9/9**.
- Latest release binary hook scan: **ABSENT**.

Still incomplete:

1. Syscall-generated error matrix is partial: short writes, EINTR, ENOSPC, EDQUOT, EIO, EROFS, fstat/open/xattr/metadata syscall errors, and cleanup/recovery errors are not comprehensively injected at the syscall boundary. Generic error post-effect classification for namespace syscalls is unproven.
2. Cleanup failure does not expose a separate cleanup status; Drop ignores unlink failure. The target commit state stayed truthful in the injected precommit test, but caller-visible cleanup truth is incomplete.
3. No actual stalled regular-filesystem syscall/deadline test or long-duration RSS growth proof.
4. SELinux/SMACK labels and character/block device nodes were not live tested; source review only. No host-capability grant to Mayi.
5. Bind-mount behavior is live tested at the core openat2 primitive in a private user/mount namespace, not through an EUID-nonzero `ExecutionContext`; this implementation intentionally refuses namespace root.
6. Independent direct-executor security audit remains required. A separate authenticated authorization-to-executor handoff review is also required before any future integration.

**OVERALL: MAYI FILESYSTEM EXECUTOR FINAL QUALIFICATION — INCOMPLETE.** Preserve ext4-only admission, EUID 0 refusal, and the disconnected filesystem core. Filesystem consumes remain `EXECUTION_DISABLED`; do not connect or enable filesystem execution.
