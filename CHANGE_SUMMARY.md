# Native structured audit logging development

Base: qualified 0.4.1-9 signed commit 4964feed6083d758391b7a196bc63305660e9275, not the dirty original main checkout or old UI prototype. Worktree: /home/eugen/projekte/mayi-journald-development, branch observability/journald-dev.

Runtime/code files: new executor/src/audit.rs and broker_audit_tests.rs; logging sites in broker.rs, pam_auth.rs, console_sessions.rs and bin/mayi-privileged-executor.rs; main.rs module registration. Package build script/tpa.json advance only this development identity; .gitignore excludes local evidence. Cargo dependencies and authorization wire protocols unchanged. Existing UI behavior is retained.

Native records replace event=... stderr audit sites. MESSAGE retains bounded readable compatibility, but fields are native and independently filterable. Queue mapping is projected from existing bounded state, view nonces are hashed, optional values omitted and exit/signal formats explicit. Dispatch, child start, completed result, failed spawn and unknown outcome are not conflated. No logging queue/thread, new database, history privilege, signing/publishing code, or runtime socket override.

All eleven requested observability documents are in this worktree root. TEST_RESULTS.md distinguishes actual runs, failed attempts and the dedicated Debian 13 lifecycle retry. REQUEST_CORRELATION.md explains why the unchanged executor/PAM protocols require a cross-service join rather than invented rq_ IDs. History CLI is deferred; journalctl reuses existing read permissions.

Earlier UI reports inherited from the baseline are historical and do not qualify this candidate. The 0.4.1-9 release/staging bundles and operator UI4 installation are not edited. Development packages stay in dist/ and qualification data outside completed release collections.


Tested runtime/package source commit: `08a4d259a6ae7e9a17afecb31ab3cd5b6d9a4724` (unsigned development commit; no release tag). Development package: `0.4.1-10~journald4 amd64`, SHA-256 `cfeb6844af4b50e55ff20003da05ee5a2a686bbdb5bcf793b64e9fa3e6aa2167`.
