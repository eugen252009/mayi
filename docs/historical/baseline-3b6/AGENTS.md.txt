# Privileged operations

- If `mayi` is available on the current machine, use it for privileged operations; run unprivileged commands normally. If `mayi` is unavailable, do not assume it exists or make it mandatory—follow the machine/project's documented privilege workflow.
- Do not bypass Mayi with `sudo`, `su`, `pkexec`, an improvised root shell, or another escalation path. For current syntax and behavior, consult `man mayi` and `man mayi-workflow` when needed.
- If Mayi rejects an operation, do not wrap it in a shell or move/copy scripts or executables to evade its restrictions. Report the blocker or find a narrower legitimate operation.
- After an approved privileged operation, verify the result with unprivileged/read-only commands where possible.
- Mayi request submission and approval are separate authorities. During actual operations, an agent may submit a request when authorized but must not invoke or automate the human approver's PAM authentication, request/accept an approver password, or handle/replay credentials. The approver must use their own interactive TTY; passwords must never be placed in argv, environment variables, or piped stdin. Automated authentication tests are allowed only in disposable qualification environments with synthetic accounts and credentials; never use real credentials or the real host.
- Approval-console authentication is per process. Do not claim authentication survives exit/restart; do not bypass it using direct broker access or another identity.

# Mayi project status

- Mayi 0.4.1-11 is the qualified stable development baseline: **STABLE — ACTIVELY MAINTAINED**. The release is immutable; the project is not shut down or indefinitely frozen. Security/correctness fixes, relevant compatibility, demonstrated usability and measured performance work continue. Future features/new platforms remain permitted when a concrete requirement justifies security impact, maintenance cost, architectural fit and testability. Feature completeness is a current assessment, not a permanent restriction. Breaking changes need explicit justification and qualification. See PROJECT_STATUS.md.
- Documentation-only work must not change runtime semantics, move release tags, rebuild/replace historical package identities, or create a new version solely for documentation. Preserve `v0.4.1` and the qualified published artifact; publication is not deployment.
- Queue/result persistence across broker restart remains **NOT CLAIMED**. The filesystem executor remains **DISCONNECTED / INCOMPLETE**. Synology DSM is not currently supported and is deferred.

# Package publication

- For a newly qualified Debian package that the task requires distributing, publish the exact qualified `.deb` through TPA.run; do not rebuild it before publication. Read `/home/eugen/projekte/tparun/docs/how-to-publish-with-tparun.md` first and follow its current workflow. Discover and confirm the existing `bootstrap` repository through TPA.run; never guess the target or create a replacement.
- Record the qualified artifact's SHA-256 and inspect package/version/architecture. Verify `tparun status` before and after staging, and confirm the staged identity and hash match. Treat package + version + architecture as immutable: if that version exists, verify its bytes and do not overwrite it; stop on a hash conflict.
- Use an isolated, refreshed APT state containing only bootstrap to check versions before and after publication. After publishing, confirm the repository advertises the package, download the exact version without installing it, and verify its SHA-256. The invariant is: qualified artifact = staged artifact = published artifact = APT-downloaded artifact.
- `tparun publish` verifies the uploaded `.deb` by SHA-256; stop if that check fails and do not rebuild the same version. This upload-integrity check and the independent APT download/hash check are complementary: one verifies the upload path, the other what consumers receive.
- Publication is not deployment. Do not install, upgrade, or restart services unless the task explicitly includes deployment. Use the existing Mayi rule for privileged deployment operations when Mayi is available.
