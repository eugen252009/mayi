# CLI compatibility

- mayi --version / -V: own build/package identity, exit0, local only.
- mayi --help / -h: concise supported usage, exit0, local only.
- mayi-approve has the same local flags; no console/PAM started for metadata.
- mayi history [options] and mayi-approve status [--json] [--watch] stay unchanged. Their --help is local.
- mayi EXEC [ARG...] preserves every argument (including empty, Unicode, spaces, --help, --version and shell metacharacters) and still requests explicit authorization.
- mayi -- EXEC [ARG...] is an unconditional executable route before internal dispatch. Same trusted-directory/ownership/path/argument validation, not a bypass.
- Unknown leading hyphen options now give MAYI_CLI_ERROR and exit12, not a misleading lookup error. Historically the fixed trusted search could resolve a filename beginning with a hyphen; use mayi -- -name for that case. Executable arguments beginning with hyphens remain untouched.
- Bare version is deliberately NOT reserved: it remains an executable name, like arbitrary unknown words. Reserving another trusted executable basename only for cosmetic aliasing would be a compatibility break. Use --version/-V. Existing reserved history/inspect/check can always be invoked as executables via --.
- Root-owned fixtures named version/history/--version/-mayi-cli-fixture are only created temporarily in disposable qualification VMs; no host trusted directory is changed.
- Missing executable after -- is usage12; empty invocation retains existing help +exit2. Existing -u analysis and --queue/--wait/--status behavior is preserved.
- Metadata combined with trailing input is rejected, not treated as child execution; after EXEC all words belong to EXEC.
- No new shell interpolation, PATH/environment lookup, root endpoint, policy, group/ACL change, privilege fallback, state restoration, release/staging selection or operator installation.
