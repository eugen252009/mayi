# ui2: less text, not more decoration

Feedback: ui1's default review was still a wall of technical text.

Next source candidate: 0.4.1-9~ui2. No ui2 package built or installed. The existing ui1 package and completed release/staging artifacts remain unchanged. Earlier reports describe ui1; this note describes the newer renderer.

A normal single request now fits one short screen:

```text
MAYI  /  Permission requested

bash  -> root
Interprets commands or runs other programs
  -c 'echo hello'
Requested by UID 1001 | One use
Time left at display: 05:00

[Space] More information

[d] Deny   [a] Approve   [q] Quit
Action + Enter:
```

Removed default argv indexes, protocol state, Unix timestamps, duplicate operation descriptions, one-page pagination labels and secondary controls. Unusual argv[0] still gets a visible warning. Long previews explicitly point to complete details. Non-pending states remain visible. Multi-request groups retain indices and explicit Approve ALL pending labeling. Expiry is a snapshot estimate, not an invented live deadline.

Space still exposes complete escaped request data, exact executable/argv, executor identity and advanced shortcuts. Page controls appear only when needed. No authorization/PAM/protocol or input-action changes. The active-input spinner now uses a short decision prompt with elapsed time, without a repeated health disclaimer or health claim.

New regression requires an ordinary 80x24 review to fit one page and at most 15 lines, retain command/privilege/wrapper information, and omit technical noise. Full serial Rust run: 104+5 passed. Formatting and strict Clippy passed. Raw logs: local-install/ui2-tests.log and ui2-clippy.log. Existing lifecycle/package qualification gaps remain; this is not UI GO. Installation of ui2 would require a new package and explicit authorization.
