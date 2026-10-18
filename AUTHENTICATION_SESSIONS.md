# Five-minute console authentication — development 0.4.1-9~ui3

## User-visible behavior

Run `mayi-approve` in your own interactive terminal. The console asks PAM to authenticate your actual Unix account once before displaying requests. An authenticated console may explicitly approve, deny, or request follow-up without another password prompt. A successful broker decision resets the idle deadline to five minutes. Incoming requests, listing, viewing, paging, typing, status checks and unsuccessful decisions do not reset it.

At five minutes without a successful decision the broker refuses the session. The console detects this on its next status tick, reports that it is locked, and exits; run `mayi-approve` again to authenticate. It does not automatically submit or approve anything after authentication. Quitting, Ctrl-C, process death, terminal hangup and broker restart invalidate authentication. The previous 120-second input timeout is now 300 seconds; broker session expiry remains the authoritative limit even inside a submenu.

This is an intentionally authorized change from per-decision passwords. Access to an unlocked console during the window permits explicit decisions without another password challenge. Leaving the console running is not equivalent to logging out. Request/view expiry and strict consumption-time TTL are independent and unchanged.

## Enforcement

- Sessions reside only in the broker's memory; no timestamp files, disk credentials, UID-wide cache, environment assertions, or persistent login state.
- A broker-generated random 192-bit session identifier is bound to kernel SO_PEERCRED UID/PID and the supplied terminal's device/inode/rdev plus Linux TIOCGDEV underlying terminal identity. This handles /dev/tty's otherwise shared device identity.
- A retained pidfd detects process death and prevents PID recycling from inheriting authentication. A retained terminal descriptor detects hangup. Authentication fails closed when pidfd/terminal checks are unavailable. New console processes, including forked children with an inherited token, cannot use the original session.
- Up to 64 active sessions, bounded independently of request storage. Expired/dead records are pruned on access/creation. Session tokens are never logged. Lifecycle audit events include only peer UID/PID, not tokens or credentials.
- Initial PAM success is checked by the existing privileged helper, with a fresh broker-generated authentication correlation ID. Broker NSS authorization is checked before and after authentication; a closed authentication connection cannot establish a session. Reauthentication first invalidates the old session, so failure cannot leave it unlocked.
- Cached decisions still require a terminal, NSS membership before and after the helper call, an unexpired matching session, a fresh bound request/view, and successful noninteractive PAM account policy. Account-only helper conversations fail closed if interaction is requested. Only the trusted broker service may invoke the helper; client fields cannot grant account-only authority.
- The session deadline is checked again under the broker lock at the actual request transition, alongside request and view deadlines. Only a successful APPROVED/DENIED/EXPLAINED response renews the session. A failed account check or session decision gate invalidates it. Logout/revocation during an in-flight decision causes the final lookup to fail.
- Role-check failure revokes the peer's cached sessions; restoring the role does not restore those sessions. As with existing NSS checks, an unobserved remove/re-add entirely between calls cannot be detected.
- The cache and final transition check both monotonic Instant and Linux CLOCK_BOOTTIME deadlines; the latter includes suspended time. Expiry on either clock locks the session. Clock failures fail closed, and wall-clock changes cannot extend validity. Both renewal deadlines are sampled before the successful transition, not after response/logging delays. Suspend behavior is tested with deterministic clock samples; physical suspend/resume remains an installed-environment qualification item.

## PAM semantics and limitations

Full `pam_authenticate` and `pam_acct_mgmt` run at session creation. Cached decisions call `pam_acct_mgmt` again with the same username-identity checks, supervisor timeout, peer/cgroup verification and terminal recovery protections, but do NOT repeat `pam_authenticate` or prompt for secrets.

This distinction is material: password changes, password-lock markers, MFA revocation or restrictions enforced only in the authentication stack may not invalidate an existing session immediately. They are re-evaluated on the next full authentication. Account expiration/restrictions actually enforced by the account stack continue to fail closed. Do not claim the historical per-decision-password/account-lock qualification unchanged. Custom PAM modules requiring interactive account management are not supported by this cached path and fail closed. Real installed PAM-stack behavior still requires disposable-environment qualification.

Same-UID memory/ptrace compromise and root are outside the isolation claim. Process binding is defense against copying a token into a different process, not protection from code already controlling the authenticated console. Session state is never transferred through exec argv/environment or restored after restart.

## Protocol additions (existing approval socket, Protocol 5)

All messages use the existing strict framing/JSON handling and actual kernel peer credentials. Each new control message carries one terminal FD via SCM_RIGHTS. Unknown fields are rejected. No requester endpoint or privileged filesystem operation was added.

- `AUTHENTICATE_CONSOLE`: exactly type, protocol, broker_instance_id. Performs PAM, returns console_session, active=true, idle_timeout_seconds=300 plus normal response correlation. It does not decide a request.
- `GET_CONSOLE_SESSION`: additionally console_session. Reports active and idle_remaining_seconds; never renews. Remaining seconds are floored, so zero may be displayed in the last fraction of a second before the strict deadline.
- `END_CONSOLE_SESSION`: same shape as status. Revokes the matching session and reports inactive. Normal console exit sends it best-effort; process-death detection is independent.
- Existing decision messages may additionally carry console_session. A provided but expired/invalid session fails closed with CONSOLE_AUTH_REQUIRED: there is no silent fallback. The broker removes only this transport-authentication field before applying the unchanged strict decision schema/binding checks.
- Legacy decisions without a session retain full per-decision PAM. No legacy response schema is changed. New consoles on old brokers fail explicitly rather than silently reducing authentication.

Helper protocol 1 gains an AUTHENTICATE_CONSOLE operation with authentication_id instead of request/view IDs. A decision helper request may contain account_only=true; its response must correlate that mode. The two shapes are disjoint. Account-only operations cannot establish a console session. Existing helper decision requests/responses retain compatibility. No new socket or elevated service is introduced.

## Tests and evidence

Local serial Rust suite: 119 broker/PAM/filesystem/UI tests + 5 executor tests PASS. Source implementation complete; installed end-to-end/security qualification remains INCONCLUSIVE. Python: 68 PASS, nine existing installed-console tests explicitly SKIPPED. Formatting and strict Clippy PASS. Retained, checksummed logs are under ui-evidence/authentication-sessions/ (session-rust-final.log, session-python.log, session-clippy-final.log and preservation evidence). ccc refresh/index timed out; no index success claimed.

New tests include:
- deterministic exact five-minute boundary, sliding renewal, repeated reads not renewing, suspend-aware expiry, clock failure, capacity and revoked-peer checks;
- token, UID, PID, terminal and broker-restart isolation; pidfd process death;
- real framed Unix sockets and SCM_RIGHTS PTYs with synthetic PAM outcomes: one login followed by approve/deny/follow-up; only account checks on cached decisions; legacy decisions still fully authenticate;
- failed reauthentication, account denial, replay, forged token, missing/wrong terminal, requester-socket misuse, malformed identity fields and wrong broker instance;
- session expiry at the final request transition, without consuming the request/view;
- NSS role denial revoking the cache; restoring membership does not restore authentication;
- real forked client unable to reuse an inherited token, controlling /dev/tty FD resolution in a receiving process, terminal hangup invalidation;
- helper schema separation, plus existing terminal supervisor SIGTERM/SIGKILL/success/failure/timeout regressions.

Synthetic PAM callbacks are test-only call sites of private functions, not a runtime flag, environment bypass, or alternate privileged endpoint. No host credentials were requested, entered, replayed or logged. No real PAM authentication was automated. Full installed login/idle/logout/relogin, actual account-policy revocation, service sandbox and Debian 11/12/13 qualification remain pending. This source implementation is not a new security qualification or production GO.

## Scope and next step

Source: /home/eugen/projekte/mayi-ui-development. Version 0.4.1-9~ui3. The installed version remains 0.4.1-9~ui1; no package was built or installed for this change. Existing ui1 artifact and rollback artifact remain unchanged. No signing, staging, publication, release tags or service restarts. Qualified 0.4.1-8 release/staging files are untouched.

Filesystem execution remains disconnected/incomplete; broker queue persistence is not claimed; TTL is strict at consumption, not guaranteed execution start; no general exactly-once side-effect guarantee. Build/install requires a separately requested candidate package and explicit installation authorization.
