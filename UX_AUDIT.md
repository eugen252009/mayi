# Initial audit — frozen baseline before implementation

Baseline ecc1ec6c4ccd5a33ee1f2b484b848f70fd642ee3 / Mayi0.4.1-10. Audit captured before application-source changes. Isolated development workspace /home/eugen/projekte/mayi-ux-development; no host approvals, installation or service changes.

Methods: actual frozen Rust renderer instrumented ONLY in a disposable source copy (capture_frozen_approval_renderings); Python human renderers with explicit validated synthetic snapshots; read-only installed help/version/error/status/history; disposable installed Debian11 PAM/PTY baseline capture. Renderer counts are layout measurements, not claims of authentication or a terminal emulator. Installed transcripts are separate.

Interfaces: Rust approval_ui View/render wraps existing broker snapshot; raw/canonical TTY input and PAM/session handling are existing broker/console_auth code. Python Waiting handles requester stderr; approval_status wraps read-only QUEUE_STATUS; history shares bounded trusted journal decoder/correlation with separate request/events views. No new framework is needed.

Confirmed HIGH: approval page-height accounting excludes wrapped chrome and clamps 8-row terminals to12. MEDIUM: executor identity hidden until details; context dependencies can precede pending action; same-epoch rq_v2 short labels collide; routine status/watch is vertically verbose; requester spinner line exceeds narrow widths. LOW: unsupported watch message has no plain human fallback; historical PENDING? and RESULT heading need clearer interpretation. Baseline shell code is already conservatively quoted and interpreter-warned: retain, do not replace with speculative natural language.

Initial artifacts are immutable audit evidence. Post-implementation tests/results belong outside audit/. Security predicates, operation order, PAM and broker state remain authoritative.
