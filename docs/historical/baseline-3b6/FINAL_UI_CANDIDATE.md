# Mayi 0.4.1-9 candidate

This candidate retains the operator-approved compact UI and five-minute broker-enforced console session policy, plus a qualification-discovered fix for catchable console termination while waiting for input. It is NOT qualified merely by having final-shaped version metadata.

Historical UI reports describe earlier snapshots and do not establish current results. The exact source and package must be independently tested; authoritative new reports live in `/home/eugen/projekte/mayi-qualification/ui-final-0.4.1-9/`. Generated test evidence is excluded from release source; historical evidence remains in prior commits/worktrees. No tag, publication, staging or host installation is authorized by this document.

The console's SIGTERM/SIGINT (also SIGHUP/SIGQUIT) handlers request cancellation instead of abruptly exiting raw input mode. The input polling loop unwinds through its existing TerminalMode guard. This does not claim recovery from SIGKILL of the console, nor prompt interruption recovery beyond independently tested PAM-child supervision. Authorization and strict consumption-time TTL are unchanged by the signal fix.

The session policy intentionally replaces a password per decision with a five-minute idle window; each request still needs an explicit decision, a bound one-shot view, fresh role/account-policy checks and strict TTL enforcement. Password-lock/MFA restrictions enforced only by pam_authenticate may not immediately revoke a preexisting session; see AUTHENTICATION_SESSIONS.md. This changed guarantee must be explicitly reviewed, not described as identical per-decision PAM semantics to 0.4.1-8.
