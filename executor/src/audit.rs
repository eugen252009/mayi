//! Best-effort native journald protocol over a nonblocking AF_UNIX datagram.
//! No runtime endpoint overrides, retries, buffers, background workers or libsystemd ABI.
use std::io;
use std::os::unix::net::UnixDatagram;

#[cfg(not(test))]
const SOCKET: &str = "/run/systemd/journal/socket";
const MAX_VALUE: usize = 256;
const MAX_FIELDS: usize = 24;
const MAX_RECORD: usize = 12 * 1024;

// Shared schema: each service intentionally emits only its available subset.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Field {
    RequestId,
    BrokerInstanceId,
    ChallengeId,
    RequestDigest,
    RequesterUid,
    ApproverUid,
    TargetUid,
    TargetGid,
    Operation,
    State,
    Result,
    ChildExitStatus,
    ChildSignal,
    Reason,
    ExecutionId,
    ViewIdHash,
    PeerUid,
    PeerPid,
    Role,
    ViewExpiresAt,
    ExecutorUid,
    ExecutorGid,
}
impl Field {
    fn name(self) -> &'static str {
        match self {
            Self::RequestId => "MAYI_REQUEST_ID",
            Self::BrokerInstanceId => "MAYI_BROKER_INSTANCE_ID",
            Self::ChallengeId => "MAYI_CHALLENGE_ID",
            Self::RequestDigest => "MAYI_REQUEST_DIGEST",
            Self::RequesterUid => "MAYI_REQUESTER_UID",
            Self::ApproverUid => "MAYI_APPROVER_UID",
            Self::TargetUid => "MAYI_TARGET_UID",
            Self::TargetGid => "MAYI_TARGET_GID",
            Self::Operation => "MAYI_OPERATION",
            Self::State => "MAYI_STATE",
            Self::Result => "MAYI_RESULT",
            Self::ChildExitStatus => "MAYI_CHILD_EXIT_STATUS",
            Self::ChildSignal => "MAYI_CHILD_SIGNAL",
            Self::Reason => "MAYI_REASON",
            Self::ExecutionId => "MAYI_EXECUTION_ID",
            Self::ViewIdHash => "MAYI_VIEW_ID_HASH",
            Self::ViewExpiresAt => "MAYI_VIEW_EXPIRES_AT",
            Self::ExecutorUid => "MAYI_EXECUTOR_UID",
            Self::ExecutorGid => "MAYI_EXECUTOR_GID",
            Self::PeerUid => "MAYI_PEER_UID",
            Self::PeerPid => "MAYI_PEER_PID",
            Self::Role => "MAYI_ROLE",
        }
    }
}
fn safe(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars().peekable();
    for c in chars.by_ref().take(MAX_VALUE) {
        let text = if c.is_ascii() && !c.is_control() {
            c.to_string()
        } else {
            format!("\\u{{{:x}}}", c as u32)
        };
        if out.len() + text.len() > MAX_VALUE - 3 {
            out.push_str("...");
            return out;
        }
        out.push_str(&text);
    }
    if chars.peek().is_some() {
        out.truncate(out.len().min(MAX_VALUE - 3));
        out.push_str("...");
    }
    out
}
fn valid_value(key: Field, value: &str) -> bool {
    fn hex(value: &str, length: usize) -> bool {
        value.len() == length
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    match key {
        Field::RequestId => value.strip_prefix("rq_").is_some_and(|v| hex(v, 32)),
        Field::ExecutionId => hex(value, 32),
        Field::BrokerInstanceId | Field::ChallengeId => hex(value, 48),
        Field::RequestDigest | Field::ViewIdHash => hex(value, 64),
        Field::RequesterUid
        | Field::ApproverUid
        | Field::TargetUid
        | Field::TargetGid
        | Field::PeerUid
        | Field::PeerPid
        | Field::Result
        | Field::ChildExitStatus
        | Field::ChildSignal
        | Field::ViewExpiresAt
        | Field::ExecutorUid
        | Field::ExecutorGid => value.parse::<u64>().is_ok_and(|n| n.to_string() == value),
        _ => true,
    }
}
fn encode(event: &str, fields: &[(Field, String)]) -> io::Result<Vec<u8>> {
    if event.is_empty()
        || event.len() > 64
        || !event
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        || fields.len() > MAX_FIELDS
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid audit schema",
        ));
    }
    let mut message = format!("event={event}");
    let mut record =
        format!("SYSLOG_IDENTIFIER=mayi\nPRIORITY=6\nMAYI_SCHEMA_VERSION=1\nMAYI_EVENT={event}\n");
    let mut seen = Vec::new();
    for (key, value) in fields {
        if !valid_value(*key, value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid audit value",
            ));
        }
        if seen.contains(key) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "duplicate audit field",
            ));
        }
        seen.push(*key);
        let value = safe(value);
        record.push_str(key.name());
        record.push('=');
        record.push_str(&value);
        record.push('\n');
        if message.len() < 700 {
            message.push(' ');
            message.push_str(&key.name()[5..].to_ascii_lowercase());
            message.push('=');
            message.push_str(&value);
        }
    }
    record.push_str("MESSAGE=");
    record.push_str(&message);
    record.push('\n');
    if record.len() > MAX_RECORD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "audit size limit",
        ));
    }
    Ok(record.into_bytes())
}
fn send(socket: &UnixDatagram, endpoint: &std::path::Path, record: &[u8]) -> io::Result<()> {
    socket.set_nonblocking(true)?;
    let size = socket.send_to(record, endpoint)?;
    if size != record.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short journal datagram",
        ));
    }
    Ok(())
}
pub(crate) fn execution_event(queued: bool, outcome: &str) -> &'static str {
    match (queued, outcome) {
        (true, "SUCCEEDED" | "FAILED") => "QUEUE_EXECUTION_FINISHED",
        (false, "SUCCEEDED" | "FAILED") => "EXECUTION_FINISHED",
        (true, "INTERNAL_ERROR" | "EXECUTION_DISABLED") => "QUEUE_DISPATCH_FAILED",
        (false, "INTERNAL_ERROR" | "EXECUTION_DISABLED") => "EXECUTION_DISPATCH_FAILED",
        (true, _) => "QUEUE_EXECUTION_OUTCOME_UNKNOWN",
        (false, _) => "EXECUTION_OUTCOME_UNKNOWN",
    }
}
pub(crate) fn emit(event: &'static str, fields: &[(Field, String)]) {
    // Errors never influence authorization. No stderr fallback: a full stderr
    // pipe must not stall a critical transition, and duplicate audit records
    // must not be mistaken for duplicate executions.
    #[cfg(not(test))]
    let _ = encode(event, fields).and_then(|record| {
        let socket = UnixDatagram::unbound()?;
        send(&socket, std::path::Path::new(SOCKET), &record)
    });
    // Unit tests validate encoding without polluting the operator journal.
    // Installed binaries always use the native transport; no runtime bypass.
    #[cfg(test)]
    let _ = encode(event, fields);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_outcome_is_never_labeled_completion() {
        for queued in [false, true] {
            for outcome in ["UNKNOWN", "EXECUTION_UNKNOWN", "malformed"] {
                assert!(execution_event(queued, outcome).ends_with("OUTCOME_UNKNOWN"));
            }
            assert!(execution_event(queued, "INTERNAL_ERROR").ends_with("DISPATCH_FAILED"));
            assert!(execution_event(queued, "SUCCEEDED").ends_with("FINISHED"));
        }
        assert!(encode("FAILED", &[(Field::ChildExitStatus, "Some(0)".into())]).is_err());
        assert!(encode("FAILED", &[(Field::RequestId, "forged".into())]).is_err());
    }
    #[test]
    fn native_fields_are_separate_and_optional_values_are_absent() {
        let bytes = encode(
            "QUEUE_EXECUTION_FINISHED",
            &[
                (
                    Field::RequestId,
                    "rq_0123456789abcdef0123456789abcdef".into(),
                ),
                (Field::ChildExitStatus, "0".into()),
            ],
        )
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.lines().any(|l| l == "MAYI_CHILD_EXIT_STATUS=0"));
        assert!(!text.contains("Some(") && !text.contains("MAYI_APPROVER_UID="));
        assert!(text.contains("\nMAYI_REQUEST_ID=rq_"));
    }
    #[test]
    fn injection_size_duplicate_and_malformed_names_are_bounded() {
        let text = String::from_utf8(
            encode("REJECTED", &[(Field::Reason, "x\n_UID=0\0\x1b".into())]).unwrap(),
        )
        .unwrap();
        assert!(!text.contains("\n_UID=") && !text.contains('\0') && !text.contains('\x1b'));
        assert!(encode("BAD\nPRIORITY=0", &[]).is_err());
        assert!(encode(
            "REJECTED",
            &[(Field::Reason, "x".into()), (Field::Reason, "y".into())]
        )
        .is_err());
        assert!(encode("REJECTED", &vec![(Field::Reason, "x".into()); 25]).is_err());
        assert!(
            encode("REJECTED", &[(Field::Reason, "z".repeat(100000))])
                .unwrap()
                .len()
                < 1024
        );
    }
    #[test]
    fn unavailable_and_saturated_sockets_return_without_retry() {
        let d = std::env::temp_dir().join(format!("mayi-audit-{}", std::process::id()));
        std::fs::create_dir(&d).unwrap();
        let endpoint = d.join("journal");
        let socket = UnixDatagram::unbound().unwrap();
        assert!(send(&socket, &endpoint, b"MAYI_EVENT=TEST\n").is_err());
        let server = UnixDatagram::bind(&endpoint).unwrap();
        let mut blocked = false;
        for _ in 0..1000 {
            if send(&socket, &endpoint, b"MAYI_EVENT=TEST\n").is_err() {
                blocked = true;
                break;
            }
        }
        assert!(blocked);
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = send(&socket, &endpoint, b"MAYI_EVENT=TEST\n");
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        drop(server);
        std::fs::remove_file(endpoint).unwrap();
        std::fs::remove_dir(d).unwrap();
    }
}
