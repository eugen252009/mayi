# Rendering security

Basename extraction uses the actual absolute bound executable string, never argv[0] or PATH. Invalid/nonabsolute/trailing-slash paths get an explicit invalid label. The broker remains authoritative. The display name is not an identity guarantee: inspect the full path in details.

render_console_arg uses safe ASCII or quoted notation; control characters, embedded newlines, ESC, Unicode/bidi are escaped. Complete detail JSON is escaped again for non-ASCII display. Previews are bounded to 100 ASCII bytes plus an explicit more-in-details marker; arguments beyond the first three are explicitly indicated. Complete rows remain reachable through pages. All pagination works on escaped ASCII, without UTF-8 slicing panics.

Non-UTF-8 paths are not representable by this existing UTF-8 JSON protocol. They remain rejected rather than lossily substituted. No encoding/protocol change. Malformed missing fields use invalid labels; LIST_PENDING structural validation is unchanged.

Known shells, interpreters and wrappers show a caution, never guessed effects. Every command has an argument count/preview and neutral execution description. Wrapper list is intentionally not an exhaustive classifier. No command execution, hashing, normalization, operation binding or privilege behavior was added to rendering.

No credentials are collected by UI code. PAM retains exclusive terminal conversation ownership during authentication; UI animation is intentionally not written over its prompts. No private keys or publication mechanism touched.
