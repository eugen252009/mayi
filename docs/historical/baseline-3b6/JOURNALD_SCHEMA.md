# Native Journald schema v1

Implementation: executor/src/audit.rs. Native single-record AF_UNIX datagrams to /run/systemd/journal/socket, using Rust's maintained std::os::unix API. This is the documented Journald native wire API, not stdout JSON or syslog text parsing. No libsystemd dependency/FFI or newer daemon ABI. Records are received with _TRANSPORT=journal; the kernel/Journald attach trusted process/unit/timestamp metadata.

Fixed envelope: SYSLOG_IDENTIFIER=mayi, PRIORITY=6, MAYI_SCHEMA_VERSION=1, MAYI_EVENT. All audit events use informational priority; filter event/state/reason, not merely journalctl -p err. Other operational CLI/startup stderr diagnostics remain separate.

| Field | Meaning / representation |
|---|---|
| MAYI_EVENT | Static uppercase lifecycle/diagnostic name |
| MAYI_REQUEST_ID | Actual broker queue ID, rq_ plus 32 lowercase hex; absent for synchronous requests |
| MAYI_BROKER_INSTANCE_ID | Existing 48-hex broker identity, where known |
| MAYI_CHALLENGE_ID | Existing 48-hex authorization challenge |
| MAYI_REQUEST_DIGEST | Existing 64-hex binding digest, not a password/token |
| MAYI_REQUESTER_UID | Broker-stored, kernel-authenticated owner |
| MAYI_APPROVER_UID | Accepted decision peer; on view events view owner; on PAM events authentication subject (not proof of an accepted decision) |
| MAYI_TARGET_UID / MAYI_TARGET_GID | Existing request-declared target metadata, as in the old logs; NOT a claim about a child's effective credentials. Existing exec requests use requester metadata while privileged execution is separate |
| MAYI_OPERATION | Validated operation available in that component: exec in broker request events; authority operation (e.g. AUTHENTICATE_CONSOLE/APPROVE_CHALLENGE) in PAM events |
| MAYI_STATE | Actual request/queue or component outcome snapshot, not inferred progress |
| MAYI_RESULT | Mayi result, e.g. 0, 14, 15, 16; not child exit status |
| MAYI_CHILD_EXIT_STATUS | Observed normal exit code; decimal, absent when unavailable/signaled |
| MAYI_CHILD_SIGNAL | Executor-observed signal number; absent for normal exit |
| MAYI_REASON | Bounded diagnostic code/ErrorKind; no arbitrary error payload or command |
| MAYI_EXECUTION_ID | Existing 32-hex executor claim ID; bridge for raw executor records, not an invented rq_ ID |
| MAYI_VIEW_ID_HASH | SHA-256 of view nonce; never the raw nonce |
| MAYI_VIEW_EXPIRES_AT | Existing view's approximate Unix expiry metadata; does not drive TTL |
| MAYI_PEER_UID / MAYI_PEER_PID | Actual available kernel peer identity |
| MAYI_ROLE | Request/approval diagnostic role |
| MAYI_EXECUTOR_UID / MAYI_EXECUTOR_GID | Executor process identity observed at actual spawn; not a promise that the approved program never changes its credentials |

Journald custom values are byte strings: journalctl JSON represents numeric fields as canonical decimal strings ("0"), never Rust Some(0)/None. Optional data is omitted, not fabricated or filled with sentinel UIDs.

Names are a closed Rust enum; no leading-underscore custom names. IDs/integers validate before encoding. Other values escape controls/non-ASCII and are bounded to 256 ASCII bytes including an omission marker. At most 24 application fields and 12 KiB per record. Duplicate keys, malformed IDs/numbers/event names and excessive fields are rejected. No complete payload serialization is used.
