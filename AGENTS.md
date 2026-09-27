# Privileged operations

- If `mayi` is available on the current machine, use it for privileged operations; run unprivileged commands normally. If `mayi` is unavailable, do not assume it exists or make it mandatory—follow the machine/project's documented privilege workflow.
- Do not bypass Mayi with `sudo`, `su`, `pkexec`, an improvised root shell, or another escalation path. For current syntax and behavior, consult `man mayi` and `man mayi-workflow` when needed.
- If Mayi rejects an operation, do not wrap it in a shell or move/copy scripts or executables to evade its restrictions. Report the blocker or find a narrower legitimate operation.
- After an approved privileged operation, verify the result with unprivileged/read-only commands where possible.
