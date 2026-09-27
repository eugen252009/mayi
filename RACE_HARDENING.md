# Race hardening — filesystem executor qualification status

The Protocol 5 broker now also supports the separate exact-command MVP. Typed filesystem operations still consume as `CONSUMED / EXECUTION_DISABLED`; the filesystem core remains disconnected.

Concurrent channel-coordinated stress now runs FilePatch same-inode changes (10,000) and FileMove destination appearance (10,000), with the racer on another thread at the precommit boundary. Existing deterministic interleavings include FilePatch pathname/symlink swaps, FileDelete changes/replacements, FileMove source changes/replacements, hardlink insertion, and parent movement (100 each); staging substitution ran 50 regular-file and 50 symlink attempts. Remaining classes are not all 10,000-iteration concurrent stress.

Test-only failure points and process `_exit` cases cover selected pre/post-commit boundaries. Patch can leave a reserved, hidden staging name after a process crash between staging-link and replacement; startup recovery reaps it under the root lock. The process-crash test is not power-loss qualification. Cleanup errors are not separately exposed; syscall-generated EINTR/ENOSPC/EDQUOT, full commit-stage injection, stalled regular-syscall bounds, and independent review remain incomplete. Private-namespace bind tests cover the openat2 primitive, not an EUID-nonzero `ExecutionContext`.

**Do not connect or enable filesystem execution.** The separate exact-command MVP does not qualify the filesystem core. See `FILESYSTEM_EXECUTOR_REMEDIATION.md` for matrices, trust limitations, and blockers.
