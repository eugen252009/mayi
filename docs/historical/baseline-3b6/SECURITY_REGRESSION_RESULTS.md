# Security regression results

The new candidate is NOT covered by 0.4.1-8 release qualification.

Repeated locally: full serial Rust broker/PAM/filesystem test suite plus executor tests; full prepared Python suite. Passing coverage includes strict consumption-time expiration, identity isolation, replay/one-shot checks, filesystem proposal rejection/disconnected execution, terminal-control escaping and PAM supervisor PTYs. PAM supervisor tests exercise normal success/failure, SIGTERM and SIGKILL child death, abnormal exit, timeout, cancellation, disconnected terminal, and preserving unrelated termios settings. They use synthetic callbacks, not actual PAM credentials.

Security-sensitive production logic was not modified: broker authorization, request canonicalization, command binding/hash, PAM helper and terminal supervisor, privileged execution, expiry deadlines and protocol schemas remain unchanged. Existing renderer injection regression now checks the complete paginated detail view. Input change adds cancellation/navigation only.

Not repeated: installed PAM service/account identity and role qualification, full Debian 11/12/13 package matrix, installed UI workflow. These must run in disposable environments with synthetic accounts before UI GO. No observed regression in tests run; absence of this mandatory evidence prevents a full security/UI sign-off.

Limitations remain: filesystem execution disconnected; no queue persistence guarantee across broker restart; strict TTL at consumption, not promised execution start; no general exactly-once side-effect guarantee.
