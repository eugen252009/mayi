# Single-line command preview (ui4)

The default approval view now displays `echo hallo`, not `echo -> root` with arguments on another line. Full executor UID/GID remains in More information. Interpreter warnings, safe escaping, bounded previews with explicit omission markers, full argument details and all authorization semantics remain unchanged.

Development version advances to 0.4.1-9~ui4 to avoid replacing the existing ui3 package identity. No new package built or installed. ui3 package and immutable release/staging directories untouched.

Focused Rust broker/UI/session suite: 64 passed, 56 unrelated main tests and 5 executor tests filtered (not a full suite run). Formatting, diff checks and strict all-targets Clippy passed. New test requires the exact single line `echo hallo`, no root suffix, and full identity/path in details. Raw logs: local-install/command-line-ui-tests.log and command-line-ui-clippy.log. Existing qualification limitations remain.
