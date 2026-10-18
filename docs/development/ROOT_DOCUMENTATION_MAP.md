# Root documentation migration map

Current entry: [Documentation Index](../INDEX.md). Repository root Markdown is
exactly README.md, PROJECT_STATUS.md and AGENTS.md. No historical evidence body
was rewritten. The21 package documents were explicit project shell inputs, not
TPA/Debian-mandated root files; build-deb.sh now maps their topic paths directly.
The security policy uses docs/SECURITY.md, also recognized by GitHub.

The table preserves old filenames as historical names; pinned source views retain
the original relative-link context. GitHub cannot redirect removed main/root URLs.
Current links and installed mayi(1) references use the destinations below.

| Former root path | Current source | Installed documentation path | Original text |
|---|---|---|---|
| `BROKER_EPOCH.md` | [docs/security/BROKER_EPOCH.md](../security/BROKER_EPOCH.md) | `/usr/share/doc/mayi/security/BROKER_EPOCH.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/BROKER_EPOCH.md) |
| `CLI_COMPATIBILITY.md` | [docs/user/CLI_COMPATIBILITY.md](../user/CLI_COMPATIBILITY.md) | `/usr/share/doc/mayi/user/CLI_COMPATIBILITY.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/CLI_COMPATIBILITY.md) |
| `CLI_DISPATCH_DESIGN.md` | [docs/architecture/CLI_DISPATCH_DESIGN.md](../architecture/CLI_DISPATCH_DESIGN.md) | `/usr/share/doc/mayi/architecture/CLI_DISPATCH_DESIGN.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/CLI_DISPATCH_DESIGN.md) |
| `EXECUTION_OUTCOME_SEMANTICS.md` | [docs/security/EXECUTION_OUTCOME_SEMANTICS.md](../security/EXECUTION_OUTCOME_SEMANTICS.md) | `/usr/share/doc/mayi/security/EXECUTION_OUTCOME_SEMANTICS.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/EXECUTION_OUTCOME_SEMANTICS.md) |
| `HISTORY_CLASSIFICATION.md` | [docs/architecture/HISTORY_CLASSIFICATION.md](../architecture/HISTORY_CLASSIFICATION.md) | `/usr/share/doc/mayi/architecture/HISTORY_CLASSIFICATION.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/HISTORY_CLASSIFICATION.md) |
| `HISTORY_CORRELATION.md` | [docs/architecture/HISTORY_CORRELATION.md](../architecture/HISTORY_CORRELATION.md) | `/usr/share/doc/mayi/architecture/HISTORY_CORRELATION.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/HISTORY_CORRELATION.md) |
| `HISTORY_DESIGN.md` | [docs/architecture/HISTORY_DESIGN.md](../architecture/HISTORY_DESIGN.md) | `/usr/share/doc/mayi/architecture/HISTORY_DESIGN.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/HISTORY_DESIGN.md) |
| `HISTORY_EVENTS_MODE.md` | [docs/user/HISTORY_EVENTS_MODE.md](../user/HISTORY_EVENTS_MODE.md) | `/usr/share/doc/mayi/user/HISTORY_EVENTS_MODE.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/HISTORY_EVENTS_MODE.md) |
| `HISTORY_JSON_COMPATIBILITY.md` | [docs/architecture/HISTORY_JSON_COMPATIBILITY.md](../architecture/HISTORY_JSON_COMPATIBILITY.md) | `/usr/share/doc/mayi/architecture/HISTORY_JSON_COMPATIBILITY.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/HISTORY_JSON_COMPATIBILITY.md) |
| `HISTORY_SCHEMA.md` | [docs/architecture/HISTORY_SCHEMA.md](../architecture/HISTORY_SCHEMA.md) | `/usr/share/doc/mayi/architecture/HISTORY_SCHEMA.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/HISTORY_SCHEMA.md) |
| `HISTORY_SECURITY.md` | [docs/security/HISTORY_SECURITY.md](../security/HISTORY_SECURITY.md) | `/usr/share/doc/mayi/security/HISTORY_SECURITY.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/HISTORY_SECURITY.md) |
| `PORTA_RECOVERY_CONTRACT.md` | [docs/architecture/PORTA_RECOVERY_CONTRACT.md](../architecture/PORTA_RECOVERY_CONTRACT.md) | `/usr/share/doc/mayi/architecture/PORTA_RECOVERY_CONTRACT.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/PORTA_RECOVERY_CONTRACT.md) |
| `QUEUE_STATE_MAPPING.md` | [docs/architecture/QUEUE_STATE_MAPPING.md](../architecture/QUEUE_STATE_MAPPING.md) | `/usr/share/doc/mayi/architecture/QUEUE_STATE_MAPPING.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/QUEUE_STATE_MAPPING.md) |
| `RESTART_INVALIDATION.md` | [docs/security/RESTART_INVALIDATION.md](../security/RESTART_INVALIDATION.md) | `/usr/share/doc/mayi/security/RESTART_INVALIDATION.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/RESTART_INVALIDATION.md) |
| `SECURITY.md` | [docs/SECURITY.md](../SECURITY.md) | `Not previously packaged; GitHub policy discovery` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/SECURITY.md) |
| `STATUS_DESIGN.md` | [docs/architecture/STATUS_DESIGN.md](../architecture/STATUS_DESIGN.md) | `/usr/share/doc/mayi/architecture/STATUS_DESIGN.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/STATUS_DESIGN.md) |
| `STATUS_JSON_SCHEMA.md` | [docs/architecture/STATUS_JSON_SCHEMA.md](../architecture/STATUS_JSON_SCHEMA.md) | `/usr/share/doc/mayi/architecture/STATUS_JSON_SCHEMA.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/STATUS_JSON_SCHEMA.md) |
| `STATUS_PROTOCOL.md` | [docs/architecture/STATUS_PROTOCOL.md](../architecture/STATUS_PROTOCOL.md) | `/usr/share/doc/mayi/architecture/STATUS_PROTOCOL.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/STATUS_PROTOCOL.md) |
| `STATUS_SECURITY.md` | [docs/security/STATUS_SECURITY.md](../security/STATUS_SECURITY.md) | `/usr/share/doc/mayi/security/STATUS_SECURITY.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/STATUS_SECURITY.md) |
| `STATUS_WATCH_MODE.md` | [docs/user/STATUS_WATCH_MODE.md](../user/STATUS_WATCH_MODE.md) | `/usr/share/doc/mayi/user/STATUS_WATCH_MODE.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/STATUS_WATCH_MODE.md) |
| `UPDATE_PREFLIGHT.md` | [docs/user/UPDATE_PREFLIGHT.md](../user/UPDATE_PREFLIGHT.md) | `/usr/share/doc/mayi/user/UPDATE_PREFLIGHT.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/UPDATE_PREFLIGHT.md) |
| `UX_USAGE.md` | [docs/user/UX_USAGE.md](../user/UX_USAGE.md) | `/usr/share/doc/mayi/user/UX_USAGE.md` | [pinned](https://github.com/eugen252009/mayi/blob/f27eeda3cc55278b74ea6f14ffa23573beca703e/UX_USAGE.md) |
