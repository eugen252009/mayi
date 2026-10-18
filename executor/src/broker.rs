//! Protocol-v5 broker-owned proposal, group-authenticated roles, approval lifecycle, and Exec handoff.
use super::{peer_uid, validate_op, MAX_MESSAGE};
use serde::de::{Deserialize, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fmt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{fs::OpenOptionsExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const VERSION: i64 = 5;
const MAX_PENDING: usize = 128;
const MAX_PENDING_PER_REQUESTER: usize = 8;
const MAX_TTL: u64 = 300;
const VIEW_MAX_LIFETIME: u64 = 60;
const WORKERS: usize = 8;
const MAX_RENDERED: usize = 32768;
const MAX_OPERATION: usize = 128 * 1024;
const PAM_AUTH_SOCKET: &str = "/run/mayi/pam-auth/auth.sock";
const PAM_AUTH_UID: u32 = 0;
const NSS_BUFFER_INITIAL: usize = 16 * 1024;
const NSS_BUFFER_MAX: usize = 1024 * 1024;
const MAX_NSS_GROUPS: usize = 65_536;
static NSS_GROUP_LOOKUP: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
struct PeerCredentials {
    pid: i32,
    uid: u32,
    gid: u32,
}

fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SO_PEERCRED size",
        ));
    }
    Ok(PeerCredentials {
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

/// None means no passwd/NSS account; Some reports membership using the NSS
/// account's primary gid and supplementary groups, not client credentials.
pub(crate) fn uid_in_group(uid: u32, role_gid: u32) -> io::Result<Option<bool>> {
    let _guard = NSS_GROUP_LOOKUP
        .lock()
        .map_err(|_| io::Error::other("NSS group lookup lock poisoned"))?;
    let mut passwd_buffer = vec![0u8; NSS_BUFFER_INITIAL];
    let (username, primary_gid) = loop {
        let mut account: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut account,
                passwd_buffer.as_mut_ptr().cast(),
                passwd_buffer.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && passwd_buffer.len() < NSS_BUFFER_MAX {
            passwd_buffer.resize((passwd_buffer.len() * 2).min(NSS_BUFFER_MAX), 0);
            continue;
        }
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        if result.is_null() {
            return Ok(None);
        }
        if account.pw_name.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NSS returned passwd entry without a username",
            ));
        }
        let username = unsafe { std::ffi::CStr::from_ptr(account.pw_name) }.to_owned();
        break (username, account.pw_gid);
    };
    if primary_gid == role_gid {
        return Ok(Some(true));
    }

    let mut groups = vec![0 as libc::gid_t; 16];
    loop {
        let mut count = i32::try_from(groups.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NSS group count overflow"))?;
        let result = unsafe {
            libc::getgrouplist(
                username.as_ptr(),
                primary_gid,
                groups.as_mut_ptr(),
                &mut count,
            )
        };
        if result >= 0 {
            let count = usize::try_from(count).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid NSS group count")
            })?;
            if count > groups.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NSS returned more groups than allocated",
                ));
            }
            return Ok(Some(groups[..count].contains(&(role_gid as libc::gid_t))));
        }
        let required = usize::try_from(count)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid NSS group count"))?;
        if required <= groups.len() || required > MAX_NSS_GROUPS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NSS group lookup failed or exceeded group limit",
            ));
        }
        groups.resize(required, 0);
    }
}

fn approval_authorization_gate<P, A, F>(
    initial: Result<(), Value>,
    preflight: P,
    authenticate: A,
    final_authorization: F,
) -> Result<(), Value>
where
    P: FnOnce() -> Result<(), Value>,
    A: FnOnce() -> Result<bool, Value>,
    F: FnOnce() -> Result<(), Value>,
{
    initial?;
    preflight()?;
    if !authenticate()? {
        return Err(response_error(
            "PAM_AUTHENTICATION_FAILED",
            "broker-side PAM authentication failed",
        ));
    }
    final_authorization()?;
    Ok(())
}

fn role_authorization(peer: PeerCredentials, role_gid: u32, approver: bool) -> Result<(), Value> {
    let role = if approver { "approver" } else { "requester" };
    let denied = |reason: String| {
        let code = if approver {
            "UNAUTHORIZED_APPROVER"
        } else {
            "UNAUTHORIZED_REQUESTER"
        };
        let mut response = response_error(code, &reason);
        response["peer_pid"] = Value::from(peer.pid);
        response["peer_uid"] = Value::from(peer.uid);
        response["peer_gid"] = Value::from(peer.gid);
        response
    };
    match uid_in_group(peer.uid, role_gid) {
        Ok(Some(true)) => Ok(()),
        Ok(Some(false)) => Err(denied(format!(
            "peer UID {} is not a member of configured {role} group GID {role_gid}",
            peer.uid
        ))),
        Ok(None) => Err(denied(format!(
            "peer UID {} has no passwd/NSS account",
            peer.uid
        ))),
        Err(error) => {
            crate::audit::emit(
                "ROLE_LOOKUP_FAILED",
                &[
                    (crate::audit::Field::Role, role.into()),
                    (crate::audit::Field::PeerPid, peer.pid.to_string()),
                    (crate::audit::Field::PeerUid, peer.uid.to_string()),
                    (crate::audit::Field::Reason, error.kind().to_string()),
                ],
            );
            Err(response_error(
                "INTERNAL_ERROR",
                &format!("{role} group lookup failed: {error}"),
            ))
        }
    }
}

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("strict JSON value")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(v.into())))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut v = Vec::new();
                while let Some(x) = a.next_element_seed(UniqueSeed)? {
                    let Unique(item) = x;
                    v.push(item)
                }
                Ok(Unique(Value::Array(v)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut m = Map::new();
                let mut seen = HashSet::new();
                while let Some(k) = a.next_key::<String>()? {
                    if !seen.insert(k.clone()) {
                        return Err(serde::de::Error::custom("duplicate object key"));
                    }
                    let Unique(v) = a.next_value_seed(UniqueSeed)?;
                    m.insert(k, v);
                }
                Ok(Unique(Value::Object(m)))
            }
        }
        d.deserialize_any(V)
    }
}
struct UniqueSeed;
impl<'de> DeserializeSeed<'de> for UniqueSeed {
    type Value = Unique;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Unique, D::Error> {
        Unique::deserialize(d)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    Proposed,
    Pending,
    Approved,
    Denied,
    Explained,
    Expired,
    Consumed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueueState {
    PendingApproval,
    WaitingDependency,
    Ready,
    Running,
    Succeeded,
    Failed,
    Denied,
    ExplainRequested,
    Expired,
    ExecutionUnknown,
    Blocked,
}
impl QueueState {
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Denied
                | Self::ExplainRequested
                | Self::Expired
                | Self::ExecutionUnknown
                | Self::Blocked
        )
    }
    fn label(self) -> &'static str {
        match self {
            Self::PendingApproval => "PENDING_APPROVAL",
            Self::WaitingDependency => "WAITING_DEPENDENCY",
            Self::Ready => "READY",
            Self::Running => "RUNNING",
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Denied => "DENIED",
            Self::ExplainRequested => "EXPLAIN_REQUESTED",
            Self::Expired => "EXPIRED",
            Self::ExecutionUnknown => "EXECUTION_UNKNOWN",
            Self::Blocked => "BLOCKED",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PolicyDecision {
    Deny,
    RequireHumanApproval,
}
fn broker_policy(op: &str) -> PolicyDecision {
    // Only the connected exact-command path may enter live approval state.
    // The direct filesystem core remains disconnected, including for queues.
    if op == "exec" {
        PolicyDecision::RequireHumanApproval
    } else {
        PolicyDecision::Deny
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum ViewState {
    Displayed,
    Approved,
    Denied,
    Explained,
    Expired,
}
#[derive(Clone)]
struct ApprovalView {
    instance: String,
    challenge: String,
    digest: String,
    approver_uid: u32,
    deadline: Instant,
    expires: i64,
    state: ViewState,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutionPhase {
    Idle,
    Dispatching,
    Started,
    Finished,
}
#[derive(Clone)]
struct Request {
    instance: String,
    challenge: String,
    digest: String,
    requester: u32,
    target_uid: u32,
    target_gid: u32,
    expires: i64,
    deadline: Instant,
    ops: Vec<Value>,
    state: State,
    request_id: Option<String>,
    dependencies: Vec<String>,
    queue_state: Option<QueueState>,
    approver_uid: Option<u32>,
    child_exit_status: Option<i32>,
    mayi_result: Option<i32>,
    blocking_dependency: Option<String>,
    execution_phase: ExecutionPhase,
}
fn request_audit_fields(r: &Request) -> Vec<(crate::audit::Field, String)> {
    use crate::audit::Field as F;
    let mut fields = vec![
        (F::BrokerInstanceId, r.instance.clone()),
        (F::ChallengeId, r.challenge.clone()),
        (F::RequestDigest, r.digest.clone()),
        (F::RequesterUid, r.requester.to_string()),
        (F::TargetUid, r.target_uid.to_string()),
        (F::TargetGid, r.target_gid.to_string()),
    ];
    if let Some(id) = &r.request_id {
        fields.push((F::RequestId, id.clone()));
    }
    if let Some(uid) = r.approver_uid {
        fields.push((F::ApproverUid, uid.to_string()));
    }
    if let Some(op) = r.ops.first().and_then(|op| op["type"].as_str()) {
        fields.push((F::Operation, op.into()));
    }
    let state = r
        .queue_state
        .map(QueueState::label)
        .unwrap_or(match r.state {
            State::Proposed => "PROPOSED",
            State::Pending => "PENDING_APPROVAL",
            State::Approved => "APPROVED",
            State::Denied => "DENIED",
            State::Explained => "EXPLAINED",
            State::Expired => "EXPIRED",
            State::Consumed => "CONSUMED",
        });
    fields.push((F::State, state.into()));
    fields
}
fn audit_request(r: &Request, event: &'static str, extra: &[(crate::audit::Field, String)]) {
    let mut fields = request_audit_fields(r);
    for (key, value) in extra {
        if let Some(field) = fields.iter_mut().find(|f| f.0 == *key) {
            field.1 = value.clone();
        } else {
            fields.push((*key, value.clone()));
        }
    }
    crate::audit::emit(event, &fields);
}
fn audit_view(
    pending: &HashMap<String, Request>,
    v: &ApprovalView,
    token: &str,
    event: &'static str,
) {
    use crate::audit::Field as F;
    let extra = vec![
        (F::ViewIdHash, token_ref(token)),
        (F::ApproverUid, v.approver_uid.to_string()),
        (F::ViewExpiresAt, v.expires.to_string()),
    ];
    if let Some(request) = pending.get(&v.challenge) {
        audit_request(request, event, &extra);
    } else {
        let mut fields = vec![
            (F::BrokerInstanceId, v.instance.clone()),
            (F::ChallengeId, v.challenge.clone()),
            (F::RequestDigest, v.digest.clone()),
        ];
        fields.extend(extra);
        crate::audit::emit(event, &fields);
    }
}
// Called under the broker mutex. The final monotonic sample at each selected
// request transition is the authorization linearization point, NOT a promise
// that IPC, process creation, or effects occur before the deadline.
fn expire_request_at(r: &mut Request, now: Instant) -> bool {
    if matches!(r.state, State::Pending | State::Approved)
        && r.queue_state != Some(QueueState::Running)
        && now >= r.deadline
    {
        let _ = transition(&mut r.state, State::Expired);
        if r.queue_state.is_some() {
            r.queue_state = Some(QueueState::Expired);
            r.mayi_result = Some(11);
        }
        audit_request(r, "EXPIRED", &[]);
    }
    r.state == State::Expired
}

#[path = "console_auth.rs"]
mod console_auth;
#[cfg(test)]
#[path = "console_session_tests.rs"]
mod console_session_tests;
#[path = "console_sessions.rs"]
mod console_sessions;

#[path = "broker_epoch.rs"]
mod broker_epoch;
#[cfg(test)]
#[path = "broker_epoch_tests.rs"]
mod broker_epoch_tests;
#[path = "queue_snapshot.rs"]
mod queue_snapshot;
#[cfg(test)]
#[path = "queue_snapshot_tests.rs"]
mod queue_snapshot_tests;
struct Broker {
    stopping: bool,
    request_id_key: [u8; 32],
    console_sessions: console_sessions::Sessions,
    // Observation-only entries bounded by the request worker pool. Keep normal
    // consumed-request retention/authorization quotas completely unchanged.
    synchronous_executions: HashMap<String, ExecutionPhase>,
    instance: String,
    challenge_counter: u64,
    view_counter: u64,
    pending: HashMap<String, Request>,
    views: HashMap<String, ApprovalView>,
}
fn token_ref(id: &str) -> String {
    let mut h = Sha256::new();
    h.update(id.as_bytes());
    hex::encode(h.finalize())
}
fn random_id() -> io::Result<String> {
    let mut b = [0u8; 24];
    fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(hex::encode(b))
}
fn valid_request_id(value: &str) -> bool {
    crate::request_ids::valid(value)
}
fn fresh_token(counter: &mut u64) -> io::Result<String> {
    let mut entropy = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut entropy)?;
    let next = counter
        .checked_add(1)
        .ok_or_else(|| io::Error::other("token counter exhausted"))?;
    let mut bytes = [0u8; 24];
    bytes[..16].copy_from_slice(&entropy);
    bytes[16..].copy_from_slice(&counter.to_be_bytes());
    *counter = next;
    Ok(hex::encode(bytes))
}
fn canonical(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let s: BTreeMap<_, _> = m.iter().collect();
            format!(
                "{{{}}}",
                s.iter()
                    .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(v)))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        _ => serde_json::to_string(v).unwrap(),
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\\' {
                "\\\\".to_string()
            } else if c.is_control() || !c.is_ascii() {
                format!("\\u{{{:04x}}}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}
fn transition(current: &mut State, next: State) -> Result<(), ()> {
    let allowed = matches!(
        (&*current, &next),
        (State::Proposed, State::Pending)
            | (State::Pending, State::Approved)
            | (State::Pending, State::Denied)
            | (State::Pending, State::Expired)
            | (State::Pending, State::Explained)
            | (State::Approved, State::Expired)
            | (State::Approved, State::Consumed)
    );
    if allowed {
        *current = next;
        Ok(())
    } else {
        Err(())
    }
}
fn transition_view(current: &mut ViewState, next: ViewState) -> Result<(), ()> {
    if *current == ViewState::Displayed
        && matches!(
            next,
            ViewState::Approved | ViewState::Denied | ViewState::Explained | ViewState::Expired
        )
    {
        *current = next;
        Ok(())
    } else {
        Err(())
    }
}
fn terminal_safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\n' {
                "\n".to_string()
            } else if c.is_control() || !c.is_ascii() {
                format!("\\u{{{:04x}}}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}
fn response_error(code: &str, msg: &str) -> Value {
    json!({"ok":false,"code":code,"message":msg,"protocol":VERSION})
}
fn valid_hex(v: Option<&Value>, len: usize) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| {
        s.len() == len
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}
fn only_keys(o: &Map<String, Value>, keys: &[&str]) -> bool {
    o.keys().all(|k| keys.contains(&k.as_str()))
}
fn canonical_path(v: Option<&Value>) -> bool {
    let Some(p) = v.and_then(Value::as_str) else {
        return false;
    };
    p.starts_with('/')
        && !p.starts_with("//")
        && !p.ends_with('/')
        && !p.contains('\0')
        && !p[1..]
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
}
fn strict_operation(o: &Value) -> bool {
    let Some(m) = o.as_object() else { return false };
    let Some(t) = m.get("type").and_then(Value::as_str) else {
        return false;
    };
    let keys = match t {
        "exec" => &["type", "executable", "argv"][..],
        "file_patch" => &[
            "type",
            "path",
            "expected_base_sha256",
            "expected_result_sha256",
            "patch",
        ][..],
        "file_create" => &["type", "path", "content", "expected_result_sha256", "mode"][..],
        "file_delete" => &["type", "path", "expected_sha256"][..],
        "file_move" => &["type", "source", "destination", "expected_source_sha256"][..],
        _ => return false,
    };
    if !only_keys(m, keys) {
        return false;
    }
    for key in ["path", "source", "destination"] {
        if m.contains_key(key) && !canonical_path(m.get(key)) {
            return false;
        }
    }
    if t == "exec" {
        let Some(executable) = m.get("executable").and_then(Value::as_str) else {
            return false;
        };
        let trusted = [
            "/usr/bin",
            "/usr/sbin",
            "/bin",
            "/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
        ];
        let Some(argv) = m.get("argv").and_then(Value::as_array) else {
            return false;
        };
        let mut total = 0usize;
        if !canonical_path(Some(&Value::String(executable.to_owned())))
            || executable.len() > 4096
            || !trusted
                .iter()
                .any(|directory| Path::new(executable).parent() == Some(Path::new(directory)))
            || fs::canonicalize(executable).ok().as_deref() != Some(Path::new(executable))
            || argv.is_empty()
            || argv.len() > 128
        {
            return false;
        }
        for arg in argv {
            let Some(value) = arg.as_str() else {
                return false;
            };
            total = total.saturating_add(value.len());
            if value.contains('\0') || value.len() > 1024 || total > 2048 {
                return false;
            }
        }
        true
    } else if t == "file_patch" {
        m.get("patch").and_then(Value::as_array).is_some_and(|a| {
            !a.is_empty()
                && a.iter().all(|e| {
                    e.as_object().is_some_and(|x| {
                        only_keys(x, &["old", "new"])
                            && x.get("old").is_some_and(Value::is_string)
                            && x.get("new").is_some_and(Value::is_string)
                    })
                })
        })
    } else {
        true
    }
}
impl Broker {
    fn dependency_graph_acyclic(&self, new_id: &str, dependencies: &[String]) -> bool {
        fn visit(
            broker: &Broker,
            new_id: &str,
            id: &str,
            active: &mut HashSet<String>,
            done: &mut HashSet<String>,
        ) -> bool {
            if id == new_id {
                return false;
            }
            if done.contains(id) {
                return true;
            }
            if !active.insert(id.to_owned()) {
                return false;
            }
            let Some(request) = broker
                .pending
                .values()
                .find(|request| request.request_id.as_deref() == Some(id))
            else {
                active.remove(id);
                return true;
            };
            for dependency in &request.dependencies {
                if !visit(broker, new_id, dependency, active, done) {
                    return false;
                }
            }
            active.remove(id);
            done.insert(id.to_owned());
            true
        }
        let mut active = HashSet::new();
        let mut done = HashSet::new();
        dependencies
            .iter()
            .all(|id| visit(self, new_id, id, &mut active, &mut done))
    }
    fn new() -> io::Result<Self> {
        let mut request_id_key = [0u8; 32];
        fs::File::open("/dev/urandom")?.read_exact(&mut request_id_key)?;
        Ok(Self {
            request_id_key,
            stopping: false,
            console_sessions: console_sessions::Sessions::default(),
            synchronous_executions: HashMap::new(),
            instance: random_id()?,
            challenge_counter: 0,
            view_counter: 0,
            pending: HashMap::new(),
            views: HashMap::new(),
        })
    }
    fn expire(&mut self) {
        for r in self.pending.values_mut() {
            if matches!(r.state, State::Pending | State::Approved)
                && r.queue_state != Some(QueueState::Running)
                && Instant::now() >= r.deadline
            {
                let _ = transition(&mut r.state, State::Expired);
                if r.queue_state.is_some() {
                    r.queue_state = Some(QueueState::Expired);
                    r.mayi_result = Some(11);
                }
                audit_request(r, "EXPIRED", &[]);
            }
        }
        let pending = &self.pending;
        for (id, v) in self.views.iter_mut() {
            if v.state == ViewState::Displayed
                && (Instant::now() >= v.deadline
                    || pending
                        .get(&v.challenge)
                        .is_none_or(|r| r.state != State::Pending))
            {
                let _ = transition_view(&mut v.state, ViewState::Expired);
                audit_view(pending, v, id, "VIEW_EXPIRED");
            }
        }
    }
    fn propose(&mut self, v: &Value, peer: u32) -> Value {
        if self.stopping {
            return self.stopping_response();
        }
        self.expire();
        let Some(o) = v.as_object() else {
            return response_error("INVALID_PROTOCOL", "message must be object");
        };
        let queued = match o.get("type").and_then(Value::as_str) {
            Some("PROPOSE_REQUEST") => false,
            Some("QUEUE_REQUEST") => true,
            _ => return response_error("INVALID_PROTOCOL", "invalid proposal type"),
        };
        let keys = if queued {
            &["type", "protocol", "target", "operations", "dependencies"][..]
        } else {
            &["type", "protocol", "target", "operations"][..]
        };
        if !only_keys(o, keys) || o.get("protocol").and_then(Value::as_i64) != Some(VERSION) {
            return response_error("INVALID_PROTOCOL", "invalid proposal schema");
        }
        let referenced: HashSet<String> = self
            .pending
            .values()
            .flat_map(|r| r.dependencies.iter().cloned())
            .collect();
        let retain_time = Instant::now();
        self.pending.retain(|_, r| {
            matches!(r.state, State::Pending | State::Approved)
                || retain_time < r.deadline
                || r.request_id
                    .as_ref()
                    .is_some_and(|id| referenced.contains(id))
        });
        let active = self
            .pending
            .values()
            .filter(|r| r.requester == peer && matches!(r.state, State::Pending | State::Approved))
            .count();
        if active >= MAX_PENDING_PER_REQUESTER {
            return response_error(
                "TOO_MANY_PENDING_REQUESTS",
                "requester pending limit reached",
            );
        }
        if self.pending.len() >= MAX_PENDING {
            return response_error("PENDING_LIMIT", "too many pending requests");
        }
        let pending = &self.pending;
        self.views.retain(|_, v| pending.contains_key(&v.challenge));
        let Some(t) = o.get("target").and_then(Value::as_object) else {
            return response_error("INVALID_PROTOCOL", "target required");
        };
        if !only_keys(t, &["uid", "gid"]) {
            return response_error("UNKNOWN_FIELD", "unknown target field");
        }
        let (Some(uid), Some(gid)) = (
            t.get("uid").and_then(Value::as_u64),
            t.get("gid").and_then(Value::as_u64),
        ) else {
            return response_error("INVALID_PROTOCOL", "numeric target uid/gid required");
        };
        if uid > u32::MAX as u64 || gid > u32::MAX as u64 {
            return response_error("INVALID_PROTOCOL", "identity out of range");
        }
        let Some(ops) = o.get("operations").and_then(Value::as_array) else {
            return response_error("INVALID_PROTOCOL", "operations array required");
        };
        let mut dependencies = Vec::new();
        if queued {
            let Some(values) = o.get("dependencies").and_then(Value::as_array) else {
                return response_error("INVALID_DEPENDENCY", "dependencies array required");
            };
            let mut seen = HashSet::new();
            for value in values {
                let Some(id) = value.as_str() else {
                    return response_error("INVALID_DEPENDENCY", "dependency ID must be a string");
                };
                if !valid_request_id(id) || !seen.insert(id.to_owned()) {
                    return response_error(
                        "INVALID_DEPENDENCY",
                        "invalid or duplicate dependency ID",
                    );
                }
                if let Some(error) = self.request_id_error(id) {
                    return error;
                }
                let Some(dep) = self
                    .pending
                    .values()
                    .find(|request| request.request_id.as_deref() == Some(id))
                else {
                    return response_error(
                        "DEPENDENCY_NOT_FOUND",
                        "dependency request is unknown or no longer retained",
                    );
                };
                if dep.requester != peer {
                    return response_error(
                        "DEPENDENCY_OWNER_MISMATCH",
                        "dependencies must belong to the authenticated requester UID",
                    );
                }
                if dep.queue_state.is_none() {
                    return response_error(
                        "INVALID_DEPENDENCY",
                        "dependency is not a queued request",
                    );
                }
                dependencies.push(id.to_owned());
            }
        }
        if ops.len() != 1 {
            return response_error(
                "INVALID_OPERATION_COUNT",
                "exactly one operation is required",
            );
        }
        let op = &ops[0];
        if queued && op.get("type").and_then(Value::as_str) != Some("exec") {
            return response_error(
                "UNSUPPORTED_OPERATION",
                "queue accepts exact exec requests only",
            );
        }
        if op.to_string().len() > MAX_OPERATION {
            return response_error("OPERATION_TOO_LARGE", "operation exceeds limit");
        }
        let Some(ty) = op.get("type").and_then(Value::as_str) else {
            return response_error("INVALID_OPERATION", "operation type required");
        };
        if broker_policy(ty) == PolicyDecision::Deny {
            return response_error(
                "UNSUPPORTED_OPERATION",
                "operation is denied by broker policy",
            );
        }
        if !strict_operation(op) {
            return response_error("UNKNOWN_FIELD", "operation schema is not exact");
        }
        if let Err(e) = validate_op(op) {
            return response_error("INVALID_OPERATION", e);
        }
        let challenge = match fresh_token(&mut self.challenge_counter) {
            Ok(id) => id,
            Err(_) => return response_error("INTERNAL_ERROR", "challenge generation failed"),
        };
        let ttl_seconds = if queued { 24 * 60 * 60 } else { MAX_TTL };
        let ttl = Duration::from_secs(ttl_seconds);
        let expires = now() + ttl_seconds as i64;
        let material = json!({"broker_instance_id":self.instance,"challenge_id":challenge,"dependencies":dependencies,"expires_at":expires,"operations":ops,"protocol":VERSION,"requester_uid":peer,"target_gid":gid,"target_uid":uid});
        let digest = hex::encode(Sha256::digest(canonical(&material).as_bytes()));
        let request_id = if queued {
            match crate::request_ids::issue(&self.request_id_key, &self.instance, &digest) {
                Ok(id)
                    if !self
                        .pending
                        .values()
                        .any(|r| r.request_id.as_deref() == Some(&id)) =>
                {
                    Some(id)
                }
                _ => return response_error("INTERNAL_ERROR", "request ID generation failed"),
            }
        } else {
            None
        };
        if queued && !self.dependency_graph_acyclic(request_id.as_deref().unwrap(), &dependencies) {
            return response_error("DEPENDENCY_CYCLE", "dependency graph must be acyclic");
        }
        let req = Request {
            instance: self.instance.clone(),
            challenge: challenge.clone(),
            digest: digest.clone(),
            requester: peer,
            target_uid: uid as u32,
            target_gid: gid as u32,
            expires,
            deadline: Instant::now() + ttl,
            ops: ops.clone(),
            state: State::Proposed,
            request_id: request_id.clone(),
            dependencies: dependencies.clone(),
            queue_state: queued.then_some(QueueState::PendingApproval),
            approver_uid: None,
            child_exit_status: None,
            mayi_result: None,
            blocking_dependency: None,
            execution_phase: ExecutionPhase::Idle,
        };
        let mut req = req;
        if transition(&mut req.state, State::Pending).is_err() {
            return response_error("INVALID_STATE_TRANSITION", "proposal transition failed");
        }
        audit_request(&req, "PROPOSED", &[]);
        self.pending.insert(challenge.clone(), req);
        if let Some(request_id) = request_id {
            audit_request(&self.pending[&challenge], "QUEUE_SUBMITTED", &[]);
            json!({"ok":true,"protocol":VERSION,"type":"QUEUE_RESPONSE","request_id":request_id,"broker_instance_id":self.instance,"challenge_id":challenge,"request_digest":digest,"status":"PENDING_APPROVAL","expires_at":expires})
        } else {
            json!({"ok":true,"protocol":VERSION,"type":"PROPOSE_RESPONSE","broker_instance_id":self.instance,"challenge_id":challenge,"request_digest":digest,"status":"PENDING_APPROVAL","expires_at":expires})
        }
    }
    fn render(&self, r: &Request, _view_id: &str, view_expires: i64) -> String {
        let mut out=format!("MAYI REQUEST\nBroker: {}\nChallenge: {}\nDigest: {}\nView expires: {}\nRequester UID: {}\nTarget UID/GID: {}/{}\nRequest expires: {}\n",r.instance,r.challenge,r.digest,view_expires,r.requester,r.target_uid,r.target_gid,r.expires);
        for op in &r.ops {
            let ty = op["type"].as_str().unwrap_or("unknown");
            if ty == "exec" {
                out.push_str("The agent requests privileged execution:\nExecutor identity: UID 0, primary GID 23012\nRequest target UID/GID (metadata only): ");
                out.push_str(&format!(
                    "{}/{}\n\nExecutable:\n",
                    r.target_uid, r.target_gid
                ));
                let executable = op["executable"].as_str().unwrap_or("<invalid>");
                out.push_str(&safe(
                    &serde_json::to_string(executable).unwrap_or_else(|_| "\"<invalid>\"".into()),
                ));
                out.push_str("\n\nArguments:\n");
                if let Some(argv) = op["argv"].as_array() {
                    for (index, arg) in argv.iter().enumerate() {
                        let value = arg.as_str().unwrap_or("<invalid>");
                        let encoded =
                            serde_json::to_string(value).unwrap_or_else(|_| "\"<invalid>\"".into());
                        out.push_str(&format!("[{}] {}\n", index, safe(&encoded)));
                    }
                }
                out.push_str("\n[y] allow once\n[n] deny\n[e] explain\n");
                continue;
            }
            out.push_str(&format!("Operation: {}\n", safe(ty)));
            for key in [
                "path",
                "source",
                "destination",
                "expected_base_sha256",
                "expected_result_sha256",
                "expected_sha256",
                "expected_source_sha256",
                "mode",
            ] {
                if let Some(v) = op.get(key) {
                    out.push_str(&format!("{}: {}\n", key, safe(v.as_str().unwrap_or(""))))
                }
            }
            if let Some(patch) = op.get("patch").and_then(Value::as_array) {
                out.push_str("Patch edits:\n");
                for e in patch {
                    out.push_str(&format!(
                        "- {}\n+ {}\n",
                        safe(e["old"].as_str().unwrap_or("")),
                        safe(e["new"].as_str().unwrap_or(""))
                    ))
                }
            }
            if let Some(content) = op.get("content").and_then(Value::as_str) {
                out.push_str(&format!("Create content (escaped): {}\n", safe(content)))
            }
        }
        out
    }
    fn validate_decision(&mut self, v: &Value, peer: u32) -> Result<(), Value> {
        self.expire();
        let Some(o) = v.as_object() else {
            return Err(response_error("INVALID_PROTOCOL", "message must be object"));
        };
        let ty = o.get("type").and_then(Value::as_str).unwrap_or("");
        if !matches!(
            ty,
            "APPROVE_CHALLENGE" | "DENY_CHALLENGE" | "EXPLAIN_CHALLENGE"
        ) {
            return Err(response_error(
                "INVALID_MESSAGE_TYPE",
                "unsupported approval message",
            ));
        }
        if !only_keys(
            o,
            &[
                "type",
                "protocol",
                "broker_instance_id",
                "challenge_id",
                "request_digest",
                "view_id",
            ],
        ) {
            return Err(response_error("UNKNOWN_FIELD", "unknown decision field"));
        }
        if o.get("protocol").and_then(Value::as_i64) != Some(VERSION)
            || o.get("broker_instance_id").and_then(Value::as_str) != Some(self.instance.as_str())
        {
            return Err(response_error(
                "BROKER_INSTANCE_MISMATCH",
                "broker instance mismatch",
            ));
        }
        let (Some(id), Some(digest), Some(view_id)) = (
            o.get("challenge_id").and_then(Value::as_str),
            o.get("request_digest").and_then(Value::as_str),
            o.get("view_id").and_then(Value::as_str),
        ) else {
            return Err(response_error(
                "INVALID_PROTOCOL",
                "challenge, digest and view ID required",
            ));
        };
        let Some(view) = self.views.get(view_id) else {
            return Err(response_error(
                "VIEW_NOT_FOUND",
                "approval view unavailable",
            ));
        };
        if view.instance != self.instance
            || view.challenge != id
            || view.digest != digest
            || view.approver_uid != peer
        {
            return Err(response_error(
                "VIEW_BINDING_MISMATCH",
                "approval view binding mismatch",
            ));
        }
        if view.state == ViewState::Expired || Instant::now() >= view.deadline {
            return Err(response_error("VIEW_EXPIRED", "approval view expired"));
        }
        if view.state != ViewState::Displayed {
            return Err(response_error(
                "VIEW_ALREADY_USED",
                "approval view is not active",
            ));
        }
        let Some(request) = self.pending.get(id) else {
            return Err(response_error(
                "CHALLENGE_NOT_FOUND",
                "challenge unavailable",
            ));
        };
        if request.digest != digest || request.challenge != id {
            return Err(response_error(
                "CHALLENGE_MISMATCH",
                "request binding mismatch",
            ));
        }
        if request.state != State::Pending {
            return Err(response_error(
                "INVALID_STATE_TRANSITION",
                "request is not pending",
            ));
        }
        if Instant::now() >= request.deadline {
            return Err(response_error("REQUEST_EXPIRED", "challenge expired"));
        }
        Ok(())
    }

    fn authority(&mut self, v: &Value, peer: u32) -> Value {
        self.authority_with_session_deadline(v, peer, None)
    }
    fn authority_with_session_deadline(
        &mut self,
        v: &Value,
        peer: u32,
        session_deadline: Option<console_sessions::Deadline>,
    ) -> Value {
        if self.stopping {
            return self.stopping_response();
        }
        self.expire();
        let Some(o) = v.as_object() else {
            return response_error("INVALID_PROTOCOL", "message must be object");
        };
        let ty = o.get("type").and_then(Value::as_str).unwrap_or("");
        match ty {
            "LIST_PENDING" => {
                if !only_keys(o, &["type", "protocol"])
                    || o.get("protocol").and_then(Value::as_i64) != Some(VERSION)
                {
                    return response_error("INVALID_PROTOCOL", "invalid list message");
                };
                let mut included: HashSet<String> = self
                    .pending
                    .values()
                    .filter(|r| {
                        r.queue_state == Some(QueueState::PendingApproval)
                            || (r.queue_state.is_none() && r.state == State::Pending)
                    })
                    .map(|r| r.challenge.clone())
                    .collect();
                loop {
                    let before = included.len();
                    let dependencies: Vec<String> = self
                        .pending
                        .iter()
                        .filter(|(key, _)| included.contains(*key))
                        .flat_map(|(_, r)| r.dependencies.iter().cloned())
                        .collect();
                    for id in dependencies {
                        if let Some((challenge, _)) = self
                            .pending
                            .iter()
                            .find(|(_, r)| r.request_id.as_deref() == Some(id.as_str()))
                        {
                            included.insert(challenge.clone());
                        }
                    }
                    let included_ids: HashSet<String> = self
                        .pending
                        .iter()
                        .filter(|(key, _)| included.contains(*key))
                        .filter_map(|(_, r)| r.request_id.clone())
                        .collect();
                    let descendants: Vec<String> = self
                        .pending
                        .iter()
                        .filter(|(_, r)| {
                            r.dependencies.iter().any(|dep| included_ids.contains(dep))
                        })
                        .map(|(key, _)| key.clone())
                        .collect();
                    included.extend(descendants);
                    if included.len() == before {
                        break;
                    }
                }
                let mut rows: Vec<_> = self.pending.values().filter(|r| included.contains(&r.challenge)).map(|r| json!({
                    "challenge_id":r.challenge,"request_digest":r.digest,"requester_uid":r.requester,"expires_at":r.expires,
                    "request_id":r.request_id,"queue_state":r.queue_state.map(QueueState::label).unwrap_or("PENDING_APPROVAL"),
                    "dependencies":r.dependencies,"operations":r.ops,"approver_uid":r.approver_uid,"blocking_dependency":r.blocking_dependency
                })).collect();
                rows.sort_by_key(|row| row["request_id"].as_str().unwrap_or("").to_owned());
                json!({"ok":true,"protocol":VERSION,"broker_instance_id":self.instance,"pending":rows})
            }
            "GET_CHALLENGE" => {
                if !only_keys(
                    o,
                    &["type", "protocol", "challenge_id", "broker_instance_id"],
                ) || o.get("protocol").and_then(Value::as_i64) != Some(VERSION)
                    || o.get("broker_instance_id").and_then(Value::as_str)
                        != Some(self.instance.as_str())
                {
                    return response_error(
                        "BROKER_INSTANCE_MISMATCH",
                        "challenge belongs to another broker",
                    );
                }
                let Some(id) = o.get("challenge_id").and_then(Value::as_str) else {
                    return response_error("INVALID_PROTOCOL", "challenge id required");
                };
                let Some(snapshot) = self.pending.get(id).cloned() else {
                    return response_error("CHALLENGE_NOT_FOUND", "challenge unavailable");
                };
                if snapshot.state != State::Pending || Instant::now() >= snapshot.deadline {
                    return response_error("INVALID_STATE_TRANSITION", "challenge is not pending");
                }
                let remaining = snapshot.deadline.saturating_duration_since(Instant::now());
                let ttl = remaining.min(Duration::from_secs(VIEW_MAX_LIFETIME));
                if ttl.is_zero() {
                    return response_error("REQUEST_EXPIRED", "challenge expired");
                }
                let view_id = match fresh_token(&mut self.view_counter) {
                    Ok(x) => x,
                    Err(_) => return response_error("INTERNAL_ERROR", "view ID generation failed"),
                };
                let view_expires = now() + ttl.as_secs().max(1) as i64;
                let rendered = self.render(&snapshot, &view_id, view_expires);
                if rendered.len() > MAX_RENDERED {
                    return response_error("RENDER_LIMIT", "approval display exceeds limit");
                }
                let stale: Vec<_> = self
                    .views
                    .iter()
                    .filter(|(_, v)| v.challenge == id)
                    .map(|(k, _)| k.clone())
                    .collect();
                for old in stale {
                    if let Some(v) = self.views.remove(&old) {
                        audit_view(&self.pending, &v, &old, "VIEW_REPLACED");
                    }
                }
                let view = ApprovalView {
                    instance: self.instance.clone(),
                    challenge: id.into(),
                    digest: snapshot.digest.clone(),
                    approver_uid: peer,
                    deadline: Instant::now() + ttl,
                    expires: view_expires,
                    state: ViewState::Displayed,
                };
                audit_view(&self.pending, &view, &view_id, "VIEW_CREATED");
                self.views.insert(view_id.clone(), view);
                json!({"ok":true,"protocol":VERSION,"type":"CHALLENGE_VIEW","status":"DISPLAYED","broker_instance_id":self.instance,"challenge_id":id,"request_digest":snapshot.digest,"view_id":view_id,"view_expires_at":view_expires,"state":"PENDING_APPROVAL","rendered":rendered})
            }
            "APPROVE_CHALLENGE" | "DENY_CHALLENGE" | "EXPLAIN_CHALLENGE" => {
                if let Err(error) = self.validate_decision(v, peer) {
                    return error;
                }
                if !only_keys(
                    o,
                    &[
                        "type",
                        "protocol",
                        "broker_instance_id",
                        "challenge_id",
                        "request_digest",
                        "view_id",
                    ],
                ) {
                    return response_error("UNKNOWN_FIELD", "unknown decision field");
                }
                if o.get("protocol").and_then(Value::as_i64) != Some(VERSION)
                    || o.get("broker_instance_id").and_then(Value::as_str)
                        != Some(self.instance.as_str())
                {
                    return response_error("BROKER_INSTANCE_MISMATCH", "broker instance mismatch");
                }
                let (Some(id), Some(d), Some(view_id)) = (
                    o.get("challenge_id").and_then(Value::as_str),
                    o.get("request_digest").and_then(Value::as_str),
                    o.get("view_id").and_then(Value::as_str),
                ) else {
                    return response_error(
                        "INVALID_PROTOCOL",
                        "challenge, digest and view ID required",
                    );
                };
                let Some(view) = self.views.get(view_id).cloned() else {
                    return response_error("VIEW_NOT_FOUND", "approval view unavailable");
                };
                if view.instance != self.instance
                    || view.challenge != id
                    || view.digest != d
                    || view.approver_uid != peer
                {
                    return response_error(
                        "VIEW_BINDING_MISMATCH",
                        "approval view binding mismatch",
                    );
                }
                if view.state == ViewState::Expired {
                    return response_error("VIEW_EXPIRED", "approval view expired");
                }
                if view.state != ViewState::Displayed {
                    return response_error("VIEW_ALREADY_USED", "approval view is not active");
                }
                if Instant::now() >= view.deadline {
                    return response_error("VIEW_EXPIRED", "approval view expired");
                }
                let Some(req) = self.pending.get(id) else {
                    return response_error("CHALLENGE_NOT_FOUND", "challenge unavailable");
                };
                if req.digest != d || req.challenge != id {
                    return response_error("CHALLENGE_MISMATCH", "request binding mismatch");
                }
                if req.state != State::Pending {
                    return response_error("INVALID_STATE_TRANSITION", "request is not pending");
                }
                if Instant::now() >= req.deadline {
                    return response_error("REQUEST_EXPIRED", "challenge expired");
                }
                let view_state = match ty {
                    "APPROVE_CHALLENGE" => ViewState::Approved,
                    "DENY_CHALLENGE" => ViewState::Denied,
                    _ => ViewState::Explained,
                };
                let request_state = match ty {
                    "APPROVE_CHALLENGE" => Some(State::Approved),
                    "DENY_CHALLENGE" => Some(State::Denied),
                    _ => Some(State::Explained),
                };
                if let Some(next) = request_state {
                    let req = self.pending.get_mut(id).unwrap();
                    let now = Instant::now();
                    if expire_request_at(req, now) {
                        return response_error("REQUEST_EXPIRED", "challenge expired");
                    }
                    if now >= view.deadline {
                        return response_error("VIEW_EXPIRED", "approval view expired");
                    }
                    if session_deadline.is_some_and(|deadline| deadline.expired(now)) {
                        return response_error("CONSOLE_AUTH_REQUIRED", "console session expired");
                    }
                    if transition(&mut req.state, next).is_err() {
                        return response_error(
                            "INVALID_STATE_TRANSITION",
                            "request transition rejected",
                        );
                    }
                    if req.queue_state.is_some() {
                        req.approver_uid = Some(peer);
                        req.queue_state = Some(match ty {
                            "APPROVE_CHALLENGE" if req.dependencies.is_empty() => QueueState::Ready,
                            "APPROVE_CHALLENGE" => QueueState::WaitingDependency,
                            "DENY_CHALLENGE" => {
                                req.mayi_result = Some(10);
                                QueueState::Denied
                            }
                            _ => {
                                req.mayi_result = Some(20);
                                QueueState::ExplainRequested
                            }
                        });
                    }
                }
                let view = self.views.get_mut(view_id).unwrap();
                if transition_view(&mut view.state, view_state).is_err() {
                    return response_error("VIEW_ALREADY_USED", "approval view already used");
                }
                let req = &self.pending[id];
                let event = match ty {
                    "APPROVE_CHALLENGE" => "VIEW_APPROVED",
                    "DENY_CHALLENGE" => "VIEW_DENIED",
                    _ => "VIEW_EXPLAINED",
                };
                audit_request(
                    req,
                    event,
                    &[
                        (crate::audit::Field::ViewIdHash, token_ref(view_id)),
                        (crate::audit::Field::ApproverUid, peer.to_string()),
                    ],
                );
                let status = match ty {
                    "APPROVE_CHALLENGE" => "APPROVED",
                    "DENY_CHALLENGE" => "DENIED",
                    _ => "EXPLAINED",
                };
                json!({"ok":true,"protocol":VERSION,"status":status,"authorized":ty=="APPROVE_CHALLENGE","broker_instance_id":self.instance,"challenge_id":id,"request_digest":d,"view_id":view_id})
            }
            _ => response_error("INVALID_MESSAGE_TYPE", "unsupported approval message"),
        }
    }
    fn consume_request(&mut self, v: &Value, peer: u32) -> Value {
        if self.stopping {
            return self.stopping_response();
        }
        self.expire();
        #[cfg(test)]
        security_regressions::after_expiry_sweep();
        let Some(o) = v.as_object() else {
            return response_error("INVALID_PROTOCOL", "message must be object");
        };
        if !only_keys(
            o,
            &[
                "type",
                "protocol",
                "broker_instance_id",
                "challenge_id",
                "request_digest",
            ],
        ) {
            return response_error("UNKNOWN_FIELD", "unknown consume field");
        }
        if o.get("type").and_then(Value::as_str) != Some("CONSUME_APPROVED")
            || o.get("protocol").and_then(Value::as_i64) != Some(VERSION)
        {
            return response_error("INVALID_PROTOCOL", "invalid consume protocol");
        }
        let (Some(instance), Some(id), Some(digest)) = (
            o.get("broker_instance_id").and_then(Value::as_str),
            o.get("challenge_id").and_then(Value::as_str),
            o.get("request_digest").and_then(Value::as_str),
        ) else {
            return response_error("INVALID_PROTOCOL", "consume identifiers required");
        };
        if !valid_hex(Some(&Value::String(instance.to_owned())), 48)
            || !valid_hex(Some(&Value::String(id.to_owned())), 48)
            || !valid_hex(Some(&Value::String(digest.to_owned())), 64)
        {
            return response_error("INVALID_PROTOCOL", "invalid consume identifiers");
        }
        if instance != self.instance {
            return self.instance_mismatch();
        }
        let Some(r) = self.pending.get_mut(id) else {
            return response_error("CHALLENGE_NOT_FOUND", "challenge unavailable");
        };
        if r.requester != peer {
            return response_error(
                "UNAUTHORIZED_REQUESTER",
                "consumer UID does not own this request",
            );
        }
        if r.instance != instance || r.challenge != id {
            return response_error("CHALLENGE_MISMATCH", "challenge binding mismatch");
        }
        if r.digest != digest {
            return response_error("CHALLENGE_MISMATCH", "digest mismatch");
        }
        if r.queue_state.is_some() {
            return response_error(
                "QUEUED_AUTO_EXECUTION",
                "queued requests execute only through the broker scheduler",
            );
        }
        match r.state {
            State::Approved => {
                // No external work between this selected-request clock sample
                // and the locked one-way claim. A stalled earlier sweep grants
                // no authority. Already dispatched execution is not cancelled.
                if expire_request_at(r, Instant::now()) {
                    return response_error("REQUEST_EXPIRED", "challenge expired");
                }
                if transition(&mut r.state, State::Consumed).is_err() {
                    return response_error(
                        "INVALID_STATE_TRANSITION",
                        "consume transition rejected",
                    );
                }
                audit_request(r, "CONSUMED", &[]);
                json!({"ok":true,"protocol":VERSION,"status":"CONSUMED","state":"CONSUMED","execution":"EXECUTION_PENDING","broker_instance_id":r.instance,"challenge_id":r.challenge,"request_digest":r.digest})
            }
            State::Consumed => {
                let mut v = response_error("ALREADY_CONSUMED", "approval already consumed");
                v["error"] = json!({"code":"REQUEST_CONSUMED"});
                v
            }
            State::Denied => {
                let mut v =
                    response_error("INVALID_STATE_TRANSITION", "operator denied authorization");
                v["error"] = json!({"code":"AUTHORITY_DENIED"});
                v
            }
            State::Expired => response_error("REQUEST_EXPIRED", "challenge expired"),
            _ => response_error("INVALID_STATE_TRANSITION", "request not approved"),
        }
    }

    fn queue_status_request(&mut self, v: &Value, peer: u32) -> Value {
        self.expire();
        let Some(object) = v.as_object() else {
            return response_error("INVALID_PROTOCOL", "message must be object");
        };
        if !only_keys(
            object,
            &["type", "protocol", "request_id", "broker_instance_id"],
        ) || object.get("type").and_then(Value::as_str) != Some("GET_QUEUE_STATUS")
            || object.get("protocol").and_then(Value::as_i64) != Some(VERSION)
        {
            return response_error("INVALID_PROTOCOL", "invalid queue status request");
        }
        let Some(id) = object.get("request_id").and_then(Value::as_str) else {
            return response_error("INVALID_REQUEST_ID", "request ID required");
        };
        if !valid_request_id(id) {
            return response_error("INVALID_REQUEST_ID", "invalid request ID");
        }
        if let Some(error) = self.request_id_error(id) {
            return error;
        }
        if let Some(instance) = object.get("broker_instance_id") {
            if !valid_hex(Some(instance), 48) {
                return response_error("INVALID_PROTOCOL", "invalid broker instance");
            }
            if instance.as_str() != Some(self.instance.as_str()) {
                return self.instance_mismatch();
            }
        }
        let Some(request) = self
            .pending
            .values()
            .find(|request| request.request_id.as_deref() == Some(id))
        else {
            return response_error(
                "REQUEST_NOT_FOUND",
                "request is unknown, expired, or invalidated by broker restart",
            );
        };
        if request.requester != peer {
            return response_error("UNAUTHORIZED_REQUESTER", "request belongs to another UID");
        }
        let Some(state) = request.queue_state else {
            return response_error("INVALID_REQUEST_ID", "request is not queued");
        };
        let authorization_error = match state {
            QueueState::Expired => Some("REQUEST_EXPIRED"),
            QueueState::Denied => Some("AUTHORITY_DENIED"),
            QueueState::ExecutionUnknown => Some("OUTCOME_UNKNOWN"),
            QueueState::Running | QueueState::Succeeded | QueueState::Failed => {
                Some("REQUEST_CONSUMED")
            }
            _ => None,
        };
        json!({"ok":true,"protocol":VERSION,"request_id":id,"epoch_id":request.instance,"authorization_error":authorization_error,"requester_uid":peer,"state":state.label(),"mayi_result":request.mayi_result,"child_exit_status":request.child_exit_status,"blocking_dependency":request.blocking_dependency,"dependencies":request.dependencies})
    }
    fn status_request(&mut self, v: &Value, peer: u32) -> Value {
        self.expire();
        let Some(o) = v.as_object() else {
            return response_error("INVALID_PROTOCOL", "message must be object");
        };
        if !only_keys(
            o,
            &[
                "type",
                "protocol",
                "broker_instance_id",
                "challenge_id",
                "request_digest",
            ],
        ) || o.get("type").and_then(Value::as_str) != Some("GET_REQUEST_STATUS")
            || o.get("protocol").and_then(Value::as_i64) != Some(VERSION)
        {
            return response_error("INVALID_PROTOCOL", "invalid status request");
        }
        let (Some(instance), Some(id), Some(digest)) = (
            o.get("broker_instance_id").and_then(Value::as_str),
            o.get("challenge_id").and_then(Value::as_str),
            o.get("request_digest").and_then(Value::as_str),
        ) else {
            return response_error("INVALID_PROTOCOL", "status identifiers required");
        };
        if !valid_hex(Some(&Value::String(instance.to_owned())), 48)
            || !valid_hex(Some(&Value::String(id.to_owned())), 48)
            || !valid_hex(Some(&Value::String(digest.to_owned())), 64)
        {
            return response_error("INVALID_PROTOCOL", "invalid status identifiers");
        }
        if instance != self.instance {
            return self.instance_mismatch();
        }
        let Some(request) = self.pending.get(id) else {
            return response_error("CHALLENGE_NOT_FOUND", "challenge unavailable");
        };
        if request.requester != peer {
            return response_error(
                "UNAUTHORIZED_REQUESTER",
                "consumer UID does not own this request",
            );
        }
        if request.instance != instance || request.challenge != id || request.digest != digest {
            return response_error("CHALLENGE_MISMATCH", "request binding mismatch");
        }
        let status = match &request.state {
            State::Pending => "PENDING",
            State::Approved => "APPROVED",
            State::Denied => "DENIED",
            State::Explained => "EXPLAINED",
            State::Expired => "EXPIRED",
            State::Consumed => "CONSUMED",
            State::Proposed => "PENDING",
        };
        json!({"ok":true,"protocol":VERSION,"status":status,"broker_instance_id":instance,"challenge_id":id,"request_digest":digest})
    }
}
fn read_exact_deadline(s: &mut UnixStream, buf: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "transaction deadline exceeded",
            ));
        }
        s.set_read_timeout(Some(left))?;
        match s.read(&mut buf[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated frame",
                ))
            }
            Ok(n) => offset += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn recv_exact_with_rights(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
    allow_rights: bool,
) -> io::Result<Option<OwnedFd>> {
    let mut offset = 0;
    let mut received_fd = None;
    while offset < buffer.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "transaction deadline exceeded",
            ));
        }
        stream.set_read_timeout(Some(left))?;
        let mut iov = libc::iovec {
            iov_base: buffer[offset..].as_mut_ptr().cast(),
            iov_len: buffer.len() - offset,
        };
        let mut control = [0usize; 16];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        let received =
            unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if received == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated frame",
            ));
        }
        offset += received as usize;
        let mut descriptors = Vec::new();
        let mut invalid_control = message.msg_flags & libc::MSG_CTRUNC != 0;
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                let header_ref = &*header;
                let base = libc::CMSG_LEN(0) as usize;
                if header_ref.cmsg_level != libc::SOL_SOCKET
                    || header_ref.cmsg_type != libc::SCM_RIGHTS
                    || header_ref.cmsg_len < base
                    || !(header_ref.cmsg_len - base)
                        .is_multiple_of(std::mem::size_of::<libc::c_int>())
                {
                    invalid_control = true;
                } else {
                    let count = (header_ref.cmsg_len - base) / std::mem::size_of::<libc::c_int>();
                    let data = libc::CMSG_DATA(header).cast::<libc::c_int>();
                    for index in 0..count {
                        let raw_fd = std::ptr::read_unaligned(data.add(index));
                        if raw_fd >= 0 {
                            descriptors.push(OwnedFd::from_raw_fd(raw_fd));
                        } else {
                            invalid_control = true;
                        }
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        if invalid_control || !descriptors.is_empty() && !allow_rights {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected socket control data",
            ));
        }
        if !descriptors.is_empty() {
            if descriptors.len() != 1 || received_fd.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected one terminal descriptor",
                ));
            }
            received_fd = descriptors.pop();
        }
    }
    Ok(received_fd)
}

fn read_frame_with_fd(
    stream: &mut UnixStream,
    deadline: Instant,
) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
    let mut header = [0; 4];
    let received_fd = recv_exact_with_rights(stream, &mut header, deadline, true)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut body = vec![0; length];
    if recv_exact_with_rights(stream, &mut body, deadline, false)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected terminal descriptor",
        ));
    }
    Ok((body, received_fd))
}

fn authenticate_through_helper_mode(
    peer_uid: u32,
    request: &Value,
    terminal_fd: RawFd,
    account_only: bool,
) -> io::Result<bool> {
    let operation = request.get("type").and_then(Value::as_str).unwrap_or("");
    let mut message = json!({
        "type": "PAM_AUTHENTICATE",
        "protocol": 1,
        "peer_uid": peer_uid,
        "operation": operation,
        "broker_instance_id": request.get("broker_instance_id"),
        "challenge_id": request.get("challenge_id"),
        "request_digest": request.get("request_digest"),
        "view_id": request.get("view_id")
    });
    if operation == "AUTHENTICATE_CONSOLE" {
        let object = message.as_object_mut().unwrap();
        for key in ["challenge_id", "request_digest", "view_id"] {
            object.remove(key);
        }
        object.insert(
            "authentication_id".into(),
            request["authentication_id"].clone(),
        );
    }
    if account_only {
        message["account_only"] = Value::Bool(true);
    }
    let deadline = Instant::now() + Duration::from_secs(310);
    let mut stream = UnixStream::connect(PAM_AUTH_SOCKET)?;
    if peer_uid_fn(&stream)? != PAM_AUTH_UID {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected PAM service peer",
        ));
    }
    send_frame_with_fd(&mut stream, &message, terminal_fd, deadline)?;
    let response = read_frame_deadline(&mut stream, deadline)?;
    let Unique(response) = serde_json::from_slice::<Unique>(&response)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid PAM service response"))?;
    let correlated = response["ok"] == true
        && response["response_to"] == "PAM_AUTHENTICATE"
        && response["peer_uid"] == peer_uid
        && response["operation"] == operation
        && response["broker_instance_id"] == message["broker_instance_id"]
        && response["challenge_id"] == message["challenge_id"]
        && response["request_digest"] == message["request_digest"]
        && response["view_id"] == message["view_id"];
    let correlated = if operation == "AUTHENTICATE_CONSOLE" {
        response["ok"] == true
            && response["response_to"] == "PAM_AUTHENTICATE"
            && response["peer_uid"] == peer_uid
            && response["operation"] == operation
            && response["broker_instance_id"] == message["broker_instance_id"]
            && response["authentication_id"] == message["authentication_id"]
    } else {
        correlated
    };
    Ok(correlated
        && response["authenticated"] == true
        && response["account_only"].as_bool().unwrap_or(false) == account_only)
}

fn peer_uid_fn(stream: &UnixStream) -> io::Result<u32> {
    peer_credentials(stream).map(|credentials| credentials.uid)
}

fn connection_usable(stream: &UnixStream) -> bool {
    let mut descriptor = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN | libc::POLLRDHUP,
        revents: 0,
    };
    if unsafe { libc::poll(&mut descriptor, 1, 0) } != 0 {
        return false;
    }
    descriptor.revents == 0
}

fn read_frame_deadline(s: &mut UnixStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut h = [0; 4];
    read_exact_deadline(s, &mut h, deadline)?;
    let n = u32::from_be_bytes(h) as usize;
    if n == 0 || n > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut b = vec![0; n];
    read_exact_deadline(s, &mut b, deadline)?;
    Ok(b)
}
fn write_all_deadline(s: &mut UnixStream, buf: &[u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "transaction deadline exceeded",
            ));
        }
        s.set_write_timeout(Some(left))?;
        match s.write(&buf[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "socket write returned zero",
                ))
            }
            Ok(n) => offset += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn write_frame_deadline(s: &mut UnixStream, v: &Value, deadline: Instant) -> io::Result<()> {
    let b = v.to_string();
    write_all_deadline(s, &(b.len() as u32).to_be_bytes(), deadline)?;
    write_all_deadline(s, b.as_bytes(), deadline)
}
fn send_frame_with_fd(
    stream: &mut UnixStream,
    message: &Value,
    terminal_fd: RawFd,
    deadline: Instant,
) -> io::Result<()> {
    let body = message.to_string();
    if body.len() > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request exceeds frame limit",
        ));
    }
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body.as_bytes());
    let mut iov = libc::iovec {
        iov_base: frame.as_mut_ptr().cast(),
        iov_len: frame.len(),
    };
    let mut control = [0usize; 8];
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize };
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&header);
        if cmsg.is_null() {
            return Err(io::Error::other(
                "could not allocate terminal descriptor control message",
            ));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), terminal_fd);
    }
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "transaction deadline exceeded",
        ));
    }
    stream.set_write_timeout(Some(left))?;
    let sent = loop {
        let count = unsafe { libc::sendmsg(stream.as_raw_fd(), &header, libc::MSG_NOSIGNAL) };
        if count >= 0 {
            break count as usize;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    if sent == 0 {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "socket write returned zero",
        ));
    }
    write_all_deadline(stream, &frame[sent..], deadline)
}

fn console_call_inner(
    path: &Path,
    broker_uid: u32,
    msg: &Value,
    terminal_fd: Option<RawFd>,
) -> io::Result<Value> {
    let timeout = if terminal_fd.is_some()
        && matches!(
            msg["type"].as_str(),
            Some(
                "AUTHENTICATE_CONSOLE"
                    | "APPROVE_CHALLENGE"
                    | "DENY_CHALLENGE"
                    | "EXPLAIN_CHALLENGE"
            )
        ) {
        Duration::from_secs(310)
    } else {
        Duration::from_secs(5)
    };
    let deadline = Instant::now() + timeout;
    let mut s = UnixStream::connect(path)?;
    if peer_uid(&s).ok() != Some(broker_uid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected broker peer UID",
        ));
    }
    if let Some(fd) = terminal_fd {
        send_frame_with_fd(&mut s, msg, fd, deadline)?;
    } else {
        write_frame_deadline(&mut s, msg, deadline)?;
    }
    let b = read_frame_deadline(&mut s, deadline)?;
    let Unique(v) = serde_json::from_slice::<Unique>(&b)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid broker response"))?;
    if v["response_to"] != msg["type"] || v["protocol"] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broker response correlation mismatch",
        ));
    }
    Ok(v)
}
fn console_call(path: &Path, broker_uid: u32, msg: &Value) -> io::Result<Value> {
    console_call_inner(path, broker_uid, msg, None)
}
fn approval_decision_call(path: &Path, broker_uid: u32, msg: &Value) -> io::Result<Value> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/tty")?;
    console_call_inner(path, broker_uid, msg, Some(tty.as_raw_fd()))
}
fn approval_call(path: &Path, broker_uid: u32, msg: &Value) -> io::Result<Value> {
    console_call(path, broker_uid, msg).map_err(|error| {
        if error.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("MAYI_UNAUTHORIZED_APPROVER: approval socket access denied: {error}"),
            )
        } else {
            error
        }
    })
}
fn check_authority_response(response: &Value) -> io::Result<()> {
    if response["ok"] == true {
        return Ok(());
    }
    let code = response["code"].as_str().unwrap_or("INTERNAL_ERROR");
    let message = response["message"]
        .as_str()
        .unwrap_or("broker rejected request");
    if code == "UNAUTHORIZED_APPROVER" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("MAYI_UNAUTHORIZED_APPROVER: {message}"),
        ));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("MAYI_BROKER_REJECTED: {code}: {message}"),
    ))
}
struct TerminalMode {
    fd: std::os::fd::RawFd,
    original: libc::termios,
}
impl TerminalMode {
    fn raw(fd: std::os::fd::RawFd) -> io::Result<Self> {
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut original) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut mode = original;
        mode.c_iflag &= !(libc::IGNCR | libc::INLCR);
        mode.c_iflag |= libc::ICRNL;
        mode.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
        mode.c_cc[libc::VMIN] = 1;
        mode.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &mode) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, original })
    }
}
impl Drop for TerminalMode {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
            libc::tcflush(self.fd, libc::TCIFLUSH);
            libc::write(libc::STDOUT_FILENO, b"\n".as_ptr().cast(), 1);
        }
    }
}
fn poll_input(fd: i32, timeout_ms: i32) -> io::Result<bool> {
    if super::broker_shutdown_requested() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "console canceled",
        ));
    }
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted && !super::broker_shutdown_requested() {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Ok(false);
        }
        if pfd.revents & libc::POLLIN != 0 {
            return Ok(true);
        }
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "terminal input closed",
        ));
    }
}
fn read_tty_frame() -> io::Result<Vec<u8>> {
    read_tty_frame_with_poll(|| Ok(()))
}
fn read_tty_frame_with_poll<F: FnMut() -> io::Result<()>>(mut on_poll: F) -> io::Result<Vec<u8>> {
    read_tty_frame_with_details(|_| on_poll(), false)
}
fn read_tty_frame_with_details<F: FnMut(Option<u8>) -> io::Result<()>>(
    mut on_event: F,
    allow_details: bool,
) -> io::Result<Vec<u8>> {
    const MAX_INPUT: usize = 64;
    const QUIET_MS: u64 = 100;
    let fd = io::stdin().as_raw_fd();
    let _terminal = TerminalMode::raw(fd)?;
    let input_deadline = Instant::now() + console_sessions::IDLE;
    let mut frame = Vec::with_capacity(MAX_INPUT);
    let mut byte = [0u8; 1];
    loop {
        let remaining = input_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "terminal input timed out",
            ));
        }
        let wait_ms = remaining.as_millis().min(1000) as i32;
        if !poll_input(fd, wait_ms)? {
            on_event(None)?;
            continue;
        }
        let read = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), byte.len()) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if read != 1 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "terminal closed",
            ));
        }
        if byte[0] == 3 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "UI canceled; no decision sent",
            ));
        }
        if allow_details && matches!(byte[0], b' ' | b'[' | b']') && frame.is_empty() {
            // Navigation only: do not return a decision or fetch another view.
            on_event(Some(byte[0]))?;
            continue;
        }
        if byte[0] == b'\n' || byte[0] == b'\r' {
            break;
        }
        if frame.len() == MAX_INPUT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "decision input too long",
            ));
        }
        frame.push(byte[0]);
    }

    // A line terminator closes one bounded input frame. Reject and drain any
    // additional bytes already queued (or arriving during the quiet window).
    let mut trailing = false;
    let drain_deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let quiet_left = drain_deadline.saturating_duration_since(Instant::now());
        if quiet_left.is_zero() {
            trailing = true;
            break;
        }
        if !poll_input(
            fd,
            quiet_left.min(Duration::from_millis(QUIET_MS)).as_millis() as i32,
        )? {
            break;
        }
        trailing = true;
        let mut discard = [0u8; 64];
        let read = unsafe { libc::read(fd, discard.as_mut_ptr().cast(), discard.len()) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if read == 0 {
            break;
        }
    }
    if trailing {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "additional terminal input after decision frame",
        ));
    }
    Ok(frame)
}
fn parse_decision(frame: &[u8]) -> Option<&'static str> {
    match frame {
        b"y" | b"approve" | b"yes" => Some("APPROVE_CHALLENGE"),
        b"n" | b"deny" | b"no" => Some("DENY_CHALLENGE"),
        b"e" | b"explain" => Some("EXPLAIN_CHALLENGE"),
        _ => None,
    }
}
#[allow(dead_code)]
fn approval_console_legacy(path: PathBuf, broker_uid: u32) -> io::Result<()> {
    if unsafe { libc::geteuid() } == 0
        || unsafe { libc::isatty(libc::STDIN_FILENO) } != 1
        || unsafe { libc::isatty(libc::STDOUT_FILENO) } != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approval console requires an unprivileged interactive terminal",
        ));
    }
    let list = approval_call(
        &path,
        broker_uid,
        &json!({"type":"LIST_PENDING","protocol":VERSION}),
    )?;
    check_authority_response(&list)?;
    if !valid_hex(list.get("broker_instance_id"), 48) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pending-list response correlation mismatch",
        ));
    }
    let instance = list["broker_instance_id"].as_str().unwrap().to_owned();
    let pending = list["pending"]
        .as_array()
        .ok_or_else(|| io::Error::other("invalid pending list"))?;
    if pending.is_empty() {
        println!("No pending mayi requests.");
        return Ok(());
    }
    if pending.len() > MAX_PENDING {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pending list exceeds broker limit",
        ));
    }
    let mut listed = HashSet::new();
    for r in pending {
        let Some(o) = r.as_object() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid pending row",
            ));
        };
        if !only_keys(
            o,
            &[
                "challenge_id",
                "request_digest",
                "requester_uid",
                "expires_at",
            ],
        ) || !valid_hex(r.get("challenge_id"), 48)
            || !valid_hex(r.get("request_digest"), 64)
            || r["requester_uid"]
                .as_u64()
                .and_then(|x| u32::try_from(x).ok())
                .is_none()
            || r["expires_at"].as_i64().is_none()
            || !listed.insert(r["challenge_id"].as_str().unwrap().to_owned())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid pending row correlation",
            ));
        }
    }
    for (i, r) in pending.iter().enumerate() {
        println!(
            "[{i}] challenge={} digest={} requester_uid={} expires_at={}",
            terminal_safe(r["challenge_id"].as_str().unwrap_or("?")),
            terminal_safe(r["request_digest"].as_str().unwrap_or("?")),
            r["requester_uid"],
            r["expires_at"]
        )
    }
    print!("Select request number (or q; input is not echoed): ");
    io::stdout().flush()?;
    let selection = read_tty_frame()?;
    let selection = std::str::from_utf8(&selection)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid selection"))?;
    if selection == "q" {
        return Ok(());
    }
    let index = selection
        .parse::<usize>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid selection"))?;
    let row = pending
        .get(index)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "selection out of range"))?;
    if !valid_hex(row.get("challenge_id"), 48) || !valid_hex(row.get("request_digest"), 64) {
        return Err(io::Error::other("invalid challenge listing identifiers"));
    }
    let challenge = row["challenge_id"].as_str().unwrap();
    let digest = row["request_digest"].as_str().unwrap();
    let view = approval_call(
        &path,
        broker_uid,
        &json!({"type":"GET_CHALLENGE","protocol":VERSION,"broker_instance_id":instance,"challenge_id":challenge}),
    )?;
    check_authority_response(&view)?;
    if view["ok"] != true
        || view["type"] != "CHALLENGE_VIEW"
        || view["broker_instance_id"] != instance
        || view["challenge_id"] != challenge
        || view["request_digest"] != digest
        || view["state"] != "PENDING_APPROVAL"
        || !valid_hex(view.get("view_id"), 48)
        || view["view_expires_at"].as_i64().is_none_or(|x| x <= now())
        || view["rendered"]
            .as_str()
            .is_none_or(|s| s.len() > MAX_RENDERED)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "challenge correlation mismatch",
        ));
    }
    println!(
        "\n{}",
        terminal_safe(
            view["rendered"]
                .as_str()
                .ok_or_else(|| io::Error::other("missing trusted rendering"))?
        )
    );
    print!("Decision [y] allow once / [n] deny / [e] explain: ");
    io::stdout().flush()?;
    let frame = read_tty_frame()?;
    let decision = parse_decision(&frame)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid decision"))?;
    let response = approval_decision_call(
        &path,
        broker_uid,
        &json!({"type":decision,"protocol":VERSION,"broker_instance_id":instance,"challenge_id":challenge,"request_digest":digest,"view_id":view["view_id"]}),
    )?;
    check_authority_response(&response)?;
    if response["broker_instance_id"] != instance
        || response["challenge_id"] != challenge
        || response["request_digest"] != digest
        || response["view_id"] != view["view_id"]
        || response["ok"] != true
        || response["status"]
            != match decision {
                "APPROVE_CHALLENGE" => "APPROVED",
                "DENY_CHALLENGE" => "DENIED",
                _ => "EXPLAINED",
            }
        || response["authorized"] != (decision == "APPROVE_CHALLENGE")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decision response correlation mismatch",
        ));
    }
    println!(
        "{} (the requester must consume an approval before execution)",
        terminal_safe(response["status"].as_str().unwrap_or("REJECTED"))
    );
    Ok(())
}
fn console_snapshot(path: &Path, broker_uid: u32) -> io::Result<(String, Vec<Value>)> {
    let response = approval_call(
        path,
        broker_uid,
        &json!({"type":"LIST_PENDING","protocol":VERSION}),
    )?;
    check_authority_response(&response)?;
    if !valid_hex(response.get("broker_instance_id"), 48) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid broker identity in pending list",
        ));
    }
    let instance = response["broker_instance_id"].as_str().unwrap().to_owned();
    let rows = response
        .get("pending")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid pending list"))?;
    if rows.len() > MAX_PENDING {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pending list exceeds broker limit",
        ));
    }
    let mut challenges = HashSet::new();
    let mut request_ids = HashSet::new();
    for row in rows {
        if !valid_hex(row.get("challenge_id"), 48)
            || !valid_hex(row.get("request_digest"), 64)
            || row.get("requester_uid").and_then(Value::as_u64).is_none()
            || row.get("queue_state").and_then(Value::as_str).is_none()
            || row.get("dependencies").and_then(Value::as_array).is_none()
            || row
                .get("operations")
                .and_then(Value::as_array)
                .is_none_or(|ops| ops.len() != 1 || ops[0]["type"] != "exec")
            || !challenges.insert(row["challenge_id"].as_str().unwrap().to_owned())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid pending request row",
            ));
        }
        if let Some(id) = row.get("request_id").and_then(Value::as_str) {
            if !valid_request_id(id) || !request_ids.insert(id.to_owned()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid or duplicate request ID in pending list",
                ));
            }
        }
        for dep in row["dependencies"].as_array().unwrap() {
            if dep.as_str().is_none_or(|id| !valid_request_id(id)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid dependency ID in pending list",
                ));
            }
        }
    }
    Ok((instance, rows.clone()))
}
fn console_row_key(row: &Value) -> String {
    row["request_id"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("sync:{}", row["challenge_id"].as_str().unwrap_or("")))
}
fn console_components(rows: &[Value]) -> io::Result<Vec<Vec<usize>>> {
    let by_id: HashMap<String, usize> = rows
        .iter()
        .enumerate()
        .filter_map(|(i, row)| row["request_id"].as_str().map(|id| (id.to_owned(), i)))
        .collect();
    let mut edges = vec![HashSet::<usize>::new(); rows.len()];
    for (i, row) in rows.iter().enumerate() {
        for dependency in row["dependencies"].as_array().unwrap() {
            let id = dependency.as_str().unwrap();
            let parent = *by_id.get(id).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pending list omitted a dependency",
                )
            })?;
            edges[i].insert(parent);
            edges[parent].insert(i);
        }
    }
    let mut seen = HashSet::new();
    let mut components = Vec::new();
    for start in 0..rows.len() {
        if !seen.insert(start) {
            continue;
        }
        let mut component = vec![start];
        let mut cursor = 0;
        while cursor < component.len() {
            let current = component[cursor];
            cursor += 1;
            for &next in &edges[current] {
                if seen.insert(next) {
                    component.push(next);
                }
            }
        }
        let mut remaining: HashSet<usize> = component.iter().copied().collect();
        let mut order = Vec::new();
        while !remaining.is_empty() {
            let mut ready: Vec<usize> = remaining
                .iter()
                .copied()
                .filter(|index| {
                    rows[*index]["dependencies"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|dep| {
                            by_id
                                .get(dep.as_str().unwrap())
                                .is_some_and(|parent| !remaining.contains(parent))
                        })
                })
                .collect();
            if ready.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "dependency graph cycle in broker listing",
                ));
            }
            ready.sort_by_key(|i| console_row_key(&rows[*i]));
            for index in ready {
                remaining.remove(&index);
                order.push(index);
            }
        }
        if order
            .iter()
            .any(|i| rows[*i]["queue_state"] == "PENDING_APPROVAL")
        {
            components.push(order);
        }
    }
    components.sort_by_key(|component| {
        component
            .first()
            .map(|i| console_row_key(&rows[*i]))
            .unwrap_or_default()
    });
    Ok(components)
}
fn console_signature(rows: &[Value], component: &[usize]) -> String {
    component
        .iter()
        .map(|i| {
            format!(
                "{}:{}",
                console_row_key(&rows[*i]),
                rows[*i]["queue_state"].as_str().unwrap_or("?")
            )
        })
        .collect::<Vec<_>>()
        .join("|")
}
fn render_console_arg(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b))
    {
        return arg.to_owned();
    }
    if arg.chars().all(|c| !c.is_control() && c.is_ascii()) && !arg.contains('\'') {
        return format!("'{}'", arg);
    }
    terminal_safe(&serde_json::to_string(arg).unwrap_or_else(|_| "\"<invalid>\"".into()))
}

const CLEAR_VISIBLE_SCREEN: &[u8] = b"\x1b[2J\x1b[H";

fn terminal_supports_visible_clear(is_tty: bool, term: Option<&str>) -> bool {
    let Some(term) = term else {
        return false;
    };
    let ansi_compatible = [
        "ansi",
        "linux",
        "vt100",
        "vt102",
        "vt220",
        "xterm",
        "screen",
        "tmux",
        "rxvt",
        "alacritty",
        "kitty",
        "wezterm",
        "foot",
        "konsole",
        "putty",
        "cygwin",
        "st",
        "Eterm",
    ]
    .iter()
    .any(|prefix| {
        term == *prefix
            || term
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('-'))
    });
    is_tty && ansi_compatible
}

fn visible_screen_clear_supported() -> bool {
    let term = std::env::var("TERM").ok();
    terminal_supports_visible_clear(
        unsafe { libc::isatty(libc::STDOUT_FILENO) } == 1,
        term.as_deref(),
    )
}

fn write_console_decision_feedback<W: Write>(
    output: &mut W,
    decision: &str,
    completed: &[usize],
    any_failed: bool,
    clear_supported: bool,
) -> io::Result<()> {
    if completed.is_empty() {
        return Ok(());
    }
    if !any_failed && clear_supported {
        let _ = output.write_all(CLEAR_VISIBLE_SCREEN);
    }
    writeln!(
        output,
        "{}: {}",
        match decision {
            "approve" => "Approved",
            "deny" => "Denied",
            _ => "Follow-up requested",
        },
        completed
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    )?;
    output.flush()
}

#[path = "approval_ui.rs"]
mod approval_ui;
#[cfg(test)]
#[path = "ui_pty_tests.rs"]
mod ui_pty_tests;
fn parse_console_subset(
    input: &str,
    rows: &[Value],
    component: &[usize],
) -> io::Result<Vec<usize>> {
    let pending: Vec<usize> = component
        .iter()
        .enumerate()
        .filter_map(|(index, row_index)| {
            (rows[*row_index]["queue_state"] == "PENDING_APPROVAL").then_some(index)
        })
        .collect();
    if input == "all" {
        return Ok(pending);
    }
    if input.is_empty() || !input.bytes().all(|b| b.is_ascii_digit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "enter 'all' or valid displayed command indices",
        ));
    }
    let mut selected = BTreeMap::new();
    for byte in input.bytes() {
        let index = (byte - b'0') as usize;
        if index >= component.len() || !pending.contains(&index) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "selection includes an unavailable command index",
            ));
        }
        selected.insert(index, ());
    }
    Ok(selected.into_keys().collect())
}
fn decide_console_row(
    path: &Path,
    broker_uid: u32,
    instance: &str,
    row: &Value,
    decision: &str,
    session: &console_auth::Console,
) -> io::Result<()> {
    let challenge = row["challenge_id"].as_str().unwrap();
    let digest = row["request_digest"].as_str().unwrap();
    let view = approval_call(
        path,
        broker_uid,
        &json!({"type":"GET_CHALLENGE","protocol":VERSION,"broker_instance_id":instance,"challenge_id":challenge}),
    )?;
    check_authority_response(&view)?;
    if view["type"] != "CHALLENGE_VIEW"
        || view["broker_instance_id"] != instance
        || view["challenge_id"] != challenge
        || view["request_digest"] != digest
        || view["state"] != "PENDING_APPROVAL"
        || !valid_hex(view.get("view_id"), 48)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "challenge view correlation mismatch",
        ));
    }
    let message = match decision {
        "approve" => "APPROVE_CHALLENGE",
        "deny" => "DENY_CHALLENGE",
        _ => "EXPLAIN_CHALLENGE",
    };
    let mut request = json!({"type":message,"protocol":VERSION,"broker_instance_id":instance,"challenge_id":challenge,"request_digest":digest,"view_id":view["view_id"]});
    session.bind(&mut request);
    let result = approval_decision_call(path, broker_uid, &request)?;
    check_authority_response(&result)?;
    let expected_status = match decision {
        "approve" => "APPROVED",
        "deny" => "DENIED",
        _ => "EXPLAINED",
    };
    if result["broker_instance_id"] != instance
        || result["challenge_id"] != challenge
        || result["request_digest"] != digest
        || result["view_id"] != view["view_id"]
        || result["status"] != expected_status
        || result["authorized"] != (decision == "approve")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decision response correlation mismatch",
        ));
    }
    Ok(())
}
fn approval_console_persistent(path: PathBuf, broker_uid: u32) -> io::Result<()> {
    if unsafe { libc::geteuid() } == 0
        || unsafe { libc::isatty(libc::STDIN_FILENO) } != 1
        || unsafe { libc::isatty(libc::STDOUT_FILENO) } != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approval console requires an unprivileged interactive terminal",
        ));
    }
    super::install_broker_shutdown_handlers();
    unsafe {
        for signal in [libc::SIGHUP, libc::SIGQUIT] {
            libc::signal(
                signal,
                super::request_broker_shutdown as *const () as libc::sighandler_t,
            );
        }
    }
    let session = console_auth::Console::authenticate(&path, broker_uid)?;
    let mut idle_announced = false;
    let mut skipped = HashSet::new();
    loop {
        session.check()?;
        let (instance, rows) = console_snapshot(&path, broker_uid)?;
        let components = console_components(&rows)?;
        if components.is_empty() {
            if !idle_announced {
                println!("Waiting for Mayi requests...");
                let _ = io::stdout().flush();
                idle_announced = true;
            }
            skipped.clear();
            if poll_input(io::stdin().as_raw_fd(), 1000)? && read_tty_frame()? == b"q" {
                return Ok(());
            }
            continue;
        }
        idle_announced = false;
        let selected_component = components
            .iter()
            .find(|component| !skipped.contains(&console_signature(&rows, component)))
            .cloned();
        let Some(component) = selected_component else {
            if poll_input(io::stdin().as_raw_fd(), 1000)? && read_tty_frame()? == b"q" {
                return Ok(());
            }
            skipped.clear();
            continue;
        };
        let signature = console_signature(&rows, &component);
        let mut view = approval_ui::View {
            details: false,
            page: 0,
        };
        view.draw(&rows, &component, None);
        let started = Instant::now();
        let mut tick = 0u64;
        let mut dimensions = approval_ui::dimensions();
        let mut announced = HashSet::from([signature.clone()]);
        let input = read_tty_frame_with_details(
            |toggle| {
                session.check()?;
                if toggle.is_some() {
                    view.draw(&rows, &component, toggle);
                    return Ok(());
                }
                let latest_dimensions = approval_ui::dimensions();
                if latest_dimensions != dimensions {
                    dimensions = latest_dimensions;
                    view.draw(&rows, &component, None);
                }
                tick += 1;
                if visible_screen_clear_supported() {
                    print!(
                        "\r\x1b[2K{}",
                        approval_ui::waiting(tick, started.elapsed().as_secs())
                    );
                    io::stdout().flush()?;
                }
                let (_, pending) = console_snapshot(&path, broker_uid)?;
                let latest_components = console_components(&pending)?;
                for set in latest_components {
                    let id = console_signature(&pending, &set);
                    if announced.insert(id) {
                        // Never print another indexed set above the current action prompt:
                        // the action still belongs to the original displayed snapshot.
                        println!("\nQueue updated. Finish or skip the current set to review it.");
                        print!("Mayi (current set) > ");
                        io::stdout().flush()?;
                    }
                }
                Ok(())
            },
            true,
        )?;
        let (current_instance, _) = console_snapshot(&path, broker_uid)?;
        if current_instance != instance {
            eprintln!("Mayi broker restarted; queued approvals were invalidated. Refreshing.");
            continue;
        }
        let input = std::str::from_utf8(&input)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid console input"))?
            .trim();
        if input == "q" {
            return Ok(());
        }
        if input == "s" {
            skipped.insert(signature);
            continue;
        }
        let (decision, selection) = match input {
            "a" | "y" | "allow" => ("approve", None),
            "d" | "n" | "deny" => {
                print!("Deny [all or indices]: ");
                io::stdout().flush()?;
                ("deny", Some(read_tty_frame_with_poll(|| session.check())?))
            }
            "f" | "e" | "explain" | "follow-up" => {
                print!("Follow up on [all or indices]: ");
                io::stdout().flush()?;
                (
                    "explain",
                    Some(read_tty_frame_with_poll(|| session.check())?),
                )
            }
            _ if input.bytes().all(|b| b.is_ascii_digit()) && !input.is_empty() => {
                ("approve", Some(input.as_bytes().to_vec()))
            }
            _ => {
                eprintln!("Invalid input; use a, s, d, f, numeric indices, or q.");
                continue;
            }
        };
        let selected = if let Some(selection) = selection {
            let selection = std::str::from_utf8(&selection)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid selection"))?;
            match parse_console_subset(selection, &rows, &component) {
                Ok(selected) => selected,
                Err(error) => {
                    eprintln!("Invalid command selection: {error}");
                    continue;
                }
            }
        } else {
            component
                .iter()
                .enumerate()
                .filter_map(|(index, row_index)| {
                    (rows[*row_index]["queue_state"] == "PENDING_APPROVAL").then_some(index)
                })
                .collect()
        };
        let mut completed = Vec::new();
        let mut any_failed = false;
        for index in selected {
            let row = &rows[component[index]];
            match decide_console_row(&path, broker_uid, &instance, row, decision, &session) {
                Ok(()) => completed.push(index),
                Err(error) => {
                    any_failed = true;
                    eprintln!("Mayi decision for [{}] was not applied: {}", index, error);
                }
            }
        }
        let clear_supported = !any_failed && visible_screen_clear_supported();
        write_console_decision_feedback(
            &mut io::stdout().lock(),
            decision,
            &completed,
            any_failed,
            clear_supported,
        )?;
    }
}

pub fn approval_console(path: PathBuf, broker_uid: u32) -> io::Result<()> {
    approval_console_persistent(path, broker_uid)
}

const PRIVILEGED_EXECUTOR_SOCKET: &str = "/run/mayi/executor/executor.sock";
const EXECUTOR_MAX_FRAME: usize = 300 * 1024;

fn call_privileged_executor(
    identity: &str,
    operation: &Value,
    started: impl FnOnce(),
    instance: &str,
) -> (Value, bool) {
    let mut completed = false;
    let outcome =
        call_privileged_executor_observed(identity, operation, &mut completed, started, instance);
    (outcome, completed)
}
fn broker_execution_event(queued: bool, outcome: &str, completed: bool) -> &'static str {
    if outcome == "FAILED" && !completed {
        return if queued {
            "QUEUE_DISPATCH_FAILED"
        } else {
            "EXECUTION_DISPATCH_FAILED"
        };
    }
    crate::audit::execution_event(queued, outcome)
}
fn call_privileged_executor_observed(
    identity: &str,
    operation: &Value,
    audit_completed: &mut bool,
    started: impl FnOnce(),
    instance: &str,
) -> Value {
    *audit_completed = false;
    let execution_identity = crate::request_ids::execution_id(identity);
    let request_id = execution_identity.as_str();
    let message = json!({
        "type": "EXEC_REQUEST_OBSERVE",
        "protocol": 1,
        "broker_instance_id": instance,
        "request_id": request_id,
        "executable": operation["executable"],
        "argv": operation["argv"]
    });
    let body = message.to_string();
    if body.len() > MAX_OPERATION {
        return json!({"execution":"INTERNAL_ERROR"});
    }
    let mut stream = match UnixStream::connect(PRIVILEGED_EXECUTOR_SOCKET) {
        Ok(stream) => stream,
        Err(_) => return json!({"execution":"INTERNAL_ERROR"}),
    };
    if peer_uid(&stream).ok() != Some(0) {
        return json!({"execution":"INTERNAL_ERROR"});
    }
    let deadline = Instant::now() + Duration::from_secs(300);
    if write_all_deadline(&mut stream, &(body.len() as u32).to_be_bytes(), deadline).is_err()
        || write_all_deadline(&mut stream, body.as_bytes(), deadline).is_err()
    {
        return json!({"execution":"UNKNOWN"});
    }
    let response = read_executor_response(&mut stream, deadline, request_id, started);
    let Ok(response) = response else {
        return json!({"execution":"UNKNOWN"});
    };
    if !response.as_object().is_some_and(|object| {
        only_keys(
            object,
            &[
                "type",
                "protocol",
                "request_id",
                "status",
                "exit_code",
                "stdout_hex",
                "stderr_hex",
                "stdout_truncated",
                "stderr_truncated",
            ],
        )
    }) || response["type"] != "EXEC_RESPONSE"
        || response["protocol"] != 1
        || response["request_id"] != request_id
    {
        return json!({"execution":"UNKNOWN"});
    }
    let status = response["status"].as_str().unwrap_or("");
    *audit_completed = status == "EXECUTED";
    let execution = match status {
        "EXECUTION_UNKNOWN" => "UNKNOWN",
        "EXECUTION_FAILED" => "FAILED",
        "EXECUTED" if response["exit_code"].as_i64() == Some(0) => "SUCCEEDED",
        "EXECUTED" => "FAILED",
        _ => "UNKNOWN",
    };
    json!({"execution":execution,"exit_code":response["exit_code"],"stdout_hex":response["stdout_hex"],"stderr_hex":response["stderr_hex"],"stdout_truncated":response["stdout_truncated"],"stderr_truncated":response["stderr_truncated"]})
}
fn read_executor_response(
    stream: &mut UnixStream,
    deadline: Instant,
    request_id: &str,
    started: impl FnOnce(),
) -> io::Result<Value> {
    let read = |stream: &mut UnixStream| {
        read_frame_deadline(stream, deadline).and_then(|bytes| {
            if bytes.len() > EXECUTOR_MAX_FRAME {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "executor response frame too large",
                ));
            }
            serde_json::from_slice::<Unique>(&bytes)
                .map(|value| value.0)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid executor response")
                })
        })
    };
    let first = read(stream)?;
    if first["type"] == "EXEC_STARTED" {
        if !first
            .as_object()
            .is_some_and(|o| only_keys(o, &["type", "protocol", "request_id"]))
            || first["protocol"] != 1
            || first["request_id"] != request_id
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid execution start observation",
            ));
        }
        started();
        let final_response = read(stream)?;
        if final_response["type"] == "EXEC_STARTED" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate execution start observation",
            ));
        }
        Ok(final_response)
    } else {
        Ok(first)
    }
}

fn run_queue_scheduler(broker: &Arc<Mutex<Broker>>) {
    let mut ready = Vec::new();
    {
        let Ok(mut state) = broker.lock() else {
            return;
        };
        if state.stopping {
            return;
        }
        state.expire();
        #[cfg(test)]
        security_regressions::after_expiry_sweep();
        let ids: Vec<String> = state
            .pending
            .values()
            .filter(|r| {
                r.queue_state == Some(QueueState::Ready)
                    || r.queue_state == Some(QueueState::WaitingDependency)
            })
            .filter_map(|r| r.request_id.clone())
            .collect();
        for id in ids {
            let Some(challenge) = state
                .pending
                .values()
                .find(|r| r.request_id.as_deref() == Some(id.as_str()))
                .map(|r| r.challenge.clone())
            else {
                continue;
            };
            let dependencies = state
                .pending
                .get(&challenge)
                .map(|r| r.dependencies.clone())
                .unwrap_or_default();
            let mut blocked_by = None;
            let mut all_succeeded = true;
            for dependency in &dependencies {
                let dep = state
                    .pending
                    .values()
                    .find(|r| r.request_id.as_deref() == Some(dependency.as_str()));
                match dep.and_then(|r| r.queue_state) {
                    Some(QueueState::Succeeded) => {}
                    Some(q) if q.terminal() => {
                        blocked_by = Some(dependency.clone());
                        break;
                    }
                    Some(_) => all_succeeded = false,
                    None => {
                        blocked_by = Some(dependency.clone());
                        break;
                    }
                }
            }
            let request = state.pending.get_mut(&challenge).unwrap();
            if expire_request_at(request, Instant::now()) {
                continue;
            }
            if let Some(dependency) = blocked_by {
                request.queue_state = Some(QueueState::Blocked);
                request.blocking_dependency = Some(dependency.clone());
                request.mayi_result = Some(14);
                request.state = State::Consumed;
                audit_request(
                    request,
                    "QUEUE_BLOCKED",
                    &[
                        (crate::audit::Field::Result, "14".into()),
                        (
                            crate::audit::Field::Reason,
                            "dependency unsuccessful".into(),
                        ),
                    ],
                );
            } else if all_succeeded {
                if request.queue_state != Some(QueueState::Running) {
                    request.queue_state = Some(QueueState::Running);
                    request.execution_phase = ExecutionPhase::Dispatching;
                    audit_request(
                        request,
                        "QUEUE_DISPATCH_STARTED",
                        &[(
                            crate::audit::Field::ExecutionId,
                            crate::request_ids::execution_id(&id),
                        )],
                    );
                    if let Some(operation) = request.ops.first().cloned() {
                        ready.push((
                            id,
                            request.instance.clone(),
                            request.requester,
                            request.approver_uid,
                            operation,
                        ));
                    } else {
                        request.queue_state = Some(QueueState::ExecutionUnknown);
                        request.mayi_result = Some(16);
                        request.state = State::Consumed;
                    }
                }
            } else {
                request.queue_state = Some(QueueState::WaitingDependency);
            }
        }
    }
    for (request_id, instance, _requester, _approver, operation) in ready {
        let worker_broker = broker.clone();
        let worker_request_id = request_id.clone();
        let spawn = std::thread::Builder::new()
            .name("mayi-queued-exec".into())
            .spawn(move || {
                let notify_started =
                    || {
                        if let Ok(mut state) = worker_broker.lock() {
                            if let Some(r) = state.pending.values_mut().find(|r| {
                                r.request_id.as_deref() == Some(worker_request_id.as_str())
                            }) {
                                if r.queue_state == Some(QueueState::Running) {
                                    r.execution_phase = ExecutionPhase::Started;
                                }
                            }
                        }
                    };
                let (outcome, audit_completed) = call_privileged_executor(
                    &worker_request_id,
                    &operation,
                    notify_started,
                    &instance,
                );
                let execution = outcome["execution"].as_str().unwrap_or("UNKNOWN");
                let child = outcome["exit_code"]
                    .as_i64()
                    .and_then(|x| i32::try_from(x).ok());
                if let Ok(mut state) = worker_broker.lock() {
                    if let Some(request) = state
                        .pending
                        .values_mut()
                        .find(|r| r.request_id.as_deref() == Some(worker_request_id.as_str()))
                    {
                        if request.queue_state == Some(QueueState::Running) {
                            let (queue_state, code) = match execution {
                                "SUCCEEDED" => (QueueState::Succeeded, 0),
                                "FAILED" => (QueueState::Failed, 14),
                                "INTERNAL_ERROR" | "EXECUTION_DISABLED" => (QueueState::Failed, 15),
                                _ => (QueueState::ExecutionUnknown, 16),
                            };
                            request.execution_phase = ExecutionPhase::Finished;
                            request.queue_state = Some(queue_state);
                            request.mayi_result = Some(code);
                            request.child_exit_status = child;
                            request.state = State::Consumed;
                            let mut fields = vec![
                                (crate::audit::Field::Result, code.to_string()),
                                (
                                    crate::audit::Field::ExecutionId,
                                    crate::request_ids::execution_id(&worker_request_id),
                                ),
                            ];
                            if let Some(child) = child {
                                fields.push((
                                    crate::audit::Field::ChildExitStatus,
                                    child.to_string(),
                                ));
                            }
                            audit_request(
                                request,
                                broker_execution_event(true, execution, audit_completed),
                                &fields,
                            );
                        }
                    }
                }
            });
        if spawn.is_err() {
            if let Ok(mut state) = broker.lock() {
                if let Some(request) = state
                    .pending
                    .values_mut()
                    .find(|r| r.request_id.as_deref() == Some(request_id.as_str()))
                {
                    request.queue_state = Some(QueueState::ExecutionUnknown);
                    request.mayi_result = Some(16);
                    request.state = State::Consumed;
                    audit_request(
                        request,
                        "QUEUE_DISPATCH_FAILED",
                        &[
                            (crate::audit::Field::Result, "16".into()),
                            (crate::audit::Field::Reason, "worker_spawn_failed".into()),
                        ],
                    );
                }
            }
        }
    }
}

fn handle(
    s: UnixStream,
    broker: &Arc<Mutex<Broker>>,
    approval: bool,
    request_gid: u32,
    approval_gid: u32,
) -> io::Result<()> {
    handle_with_auth(
        s,
        broker,
        approval,
        request_gid,
        approval_gid,
        &authenticate_through_helper_mode,
    )
}
fn handle_with_auth(
    mut s: UnixStream,
    broker: &Arc<Mutex<Broker>>,
    approval: bool,
    request_gid: u32,
    approval_gid: u32,
    authenticate: &impl Fn(u32, &Value, RawFd, bool) -> io::Result<bool>,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    let credentials = peer_credentials(&s);
    let peer = credentials
        .as_ref()
        .map(|peer| peer.uid)
        .unwrap_or(u32::MAX);
    let (mut v, terminal_fd) = match read_frame_with_fd(&mut s, deadline).and_then(|(b, fd)| {
        serde_json::from_slice::<Unique>(&b)
            .map(|u| (u.0, fd))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid JSON"))
    }) {
        Ok(message) => message,
        Err(_) => {
            let mut error = response_error("INVALID_PROTOCOL", "invalid framed JSON");
            let instance = broker
                .lock()
                .map_err(|_| io::Error::other("broker state poisoned"))?
                .instance
                .clone();
            if let Some(m) = error.as_object_mut() {
                m.insert("broker_instance_id".into(), Value::String(instance));
                m.insert("response_to".into(), Value::Null);
            }
            let _ = write_frame_deadline(&mut s, &error, deadline);
            return Ok(());
        }
    };
    let role_gid = if approval { approval_gid } else { request_gid };
    let peer_credentials_snapshot = credentials.as_ref().ok().copied();
    let authorization = match credentials {
        Ok(credentials) => role_authorization(credentials, role_gid, approval),
        Err(error) => Err(response_error(
            "INTERNAL_ERROR",
            &format!("SO_PEERCRED lookup failed: {error}"),
        )),
    };
    if v["type"] == "QUEUE_STATUS" {
        let response = if !approval {
            response_error(
                "UNAUTHORIZED_ROLE",
                "queue snapshot requires approval socket",
            )
        } else if let Err(error) = authorization {
            error
        } else if terminal_fd.is_some()
            || !v
                .as_object()
                .is_some_and(|o| only_keys(o, &["type", "protocol"]))
            || v["protocol"] != VERSION
        {
            response_error("INVALID_PROTOCOL", "invalid queue snapshot message")
        } else {
            broker
                .lock()
                .map_err(|_| io::Error::other("broker state poisoned"))?
                .queue_snapshot()
        };
        let mut response = response;
        response["response_to"] = json!("QUEUE_STATUS");
        return write_frame_deadline(&mut s, &response, deadline);
    }
    if authorization.is_err() {
        if let Some(peer) = peer_credentials_snapshot {
            broker
                .lock()
                .map_err(|_| io::Error::other("broker state poisoned"))?
                .console_sessions
                .revoke_peer(peer);
        }
    }
    if approval
        && matches!(
            v["type"].as_str(),
            Some("AUTHENTICATE_CONSOLE" | "GET_CONSOLE_SESSION" | "END_CONSOLE_SESSION")
        )
    {
        let mut response = match (authorization, peer_credentials_snapshot) {
            (Ok(()), Some(peer)) => console_auth::control(
                &s,
                broker,
                peer,
                role_gid,
                &v,
                terminal_fd.as_ref(),
                authenticate,
            ),
            (Err(error), _) => error,
            _ => response_error("INTERNAL_ERROR", "peer identity unavailable"),
        };
        response["broker_instance_id"] = Value::String(
            broker
                .lock()
                .map_err(|_| io::Error::other("broker state poisoned"))?
                .instance
                .clone(),
        );
        response["response_to"] = v["type"].clone();
        return write_frame_deadline(&mut s, &response, Instant::now() + Duration::from_secs(5));
    }
    let is_decision = approval
        && matches!(
            v["type"].as_str(),
            Some("APPROVE_CHALLENGE" | "DENY_CHALLENGE" | "EXPLAIN_CHALLENGE")
        );
    let session_token = if is_decision {
        v.as_object_mut().and_then(|o| o.remove("console_session"))
    } else {
        None
    };
    let session_key = peer_credentials_snapshot
        .zip(terminal_fd.as_ref())
        .and_then(|(peer, fd)| console_sessions::Key::from_peer(peer, fd.as_raw_fd()).ok());
    let message_type = v.get("type").and_then(Value::as_str).unwrap_or("");
    let decision_operation = approval
        && matches!(
            message_type,
            "APPROVE_CHALLENGE" | "DENY_CHALLENGE" | "EXPLAIN_CHALLENGE"
        );
    let mut pam_authenticated = false;
    let mut authentication_error = if decision_operation {
        let initial_authorization = authorization.clone();
        let gate_result = approval_authorization_gate(
            initial_authorization,
            || {
                broker
                    .lock()
                    .map_err(|_| response_error("INTERNAL_ERROR", "broker state poisoned"))?
                    .validate_decision(&v, peer)
            },
            || {
                if let Some(token) = session_token.as_ref() {
                    let valid = session_key.zip(token.as_str()).is_some_and(|(key, token)| {
                        broker.lock().is_ok_and(|mut state| {
                            state
                                .console_sessions
                                .deadline(key, token, Instant::now())
                                .is_some()
                        })
                    });
                    if !valid {
                        return Err(response_error(
                            "CONSOLE_AUTH_REQUIRED",
                            "console session expired or invalid",
                        ));
                    }
                    let ok = terminal_fd.as_ref().is_some_and(|fd| {
                        authenticate(peer, &v, fd.as_raw_fd(), true).unwrap_or(false)
                    });
                    if !ok {
                        if let Some(key) = session_key {
                            if let Ok(mut state) = broker.lock() {
                                state.console_sessions.revoke(key);
                            }
                        }
                        return Err(response_error(
                            "PAM_AUTHENTICATION_FAILED",
                            "account policy check failed; authenticate again",
                        ));
                    }
                    return Ok(connection_usable(&s));
                }
                match terminal_fd.as_ref() {
                    None => Err(response_error(
                        "PAM_AUTH_REQUIRED",
                        "approval decisions require broker-side PAM authentication",
                    )),
                    Some(fd) => match authenticate(peer, &v, fd.as_raw_fd(), false) {
                        Ok(true) if connection_usable(&s) => Ok(true),
                        Ok(true) => Err(response_error(
                            "AUTHENTICATION_CONNECTION_CLOSED",
                            "approval connection closed during authentication",
                        )),
                        Ok(false) | Err(_) => Err(response_error(
                            "PAM_AUTHENTICATION_FAILED",
                            "broker-side PAM authentication failed",
                        )),
                    },
                }
            },
            || match peer_credentials_snapshot {
                Some(credentials) => role_authorization(credentials, role_gid, true),
                None => Err(response_error(
                    "INTERNAL_ERROR",
                    "SO_PEERCRED lookup failed before approval transition",
                )),
            },
        );
        pam_authenticated = gate_result.is_ok();
        if !pam_authenticated && session_token.is_some() {
            if let Some(key) = session_key {
                broker
                    .lock()
                    .map_err(|_| io::Error::other("broker state poisoned"))?
                    .console_sessions
                    .revoke(key);
            }
        }
        gate_result.err()
    } else {
        None
    };
    if terminal_fd.is_some() && !decision_operation {
        authentication_error = Some(response_error(
            "UNEXPECTED_AUTH_DESCRIPTOR",
            "terminal descriptors are accepted only for approval decisions",
        ));
    }
    let mut state = broker
        .lock()
        .map_err(|_| io::Error::other("broker state poisoned"))?;
    let mut r = if state.stopping {
        state.stopping_response()
    } else {
        match authentication_error {
            Some(error) => error,
            None => match authorization {
                Err(error) => error,
                Ok(()) if approval && decision_operation && pam_authenticated => {
                    match state.validate_decision(&v, peer) {
                        Ok(()) => console_auth::apply_decision(
                            &mut state,
                            &v,
                            peer,
                            session_key,
                            session_token.as_ref(),
                        ),
                        Err(error) => error,
                    }
                }
                Ok(()) if approval && decision_operation => response_error(
                    "PAM_AUTHENTICATION_FAILED",
                    "approval decision lacks successful PAM authentication",
                ),
                Ok(()) if approval => state.authority(&v, peer),
                Ok(()) if message_type == "CONSUME_APPROVED" => state.consume_request(&v, peer),
                Ok(()) if message_type == "GET_REQUEST_STATUS" => state.status_request(&v, peer),
                Ok(()) if message_type == "GET_QUEUE_STATUS" => {
                    state.queue_status_request(&v, peer)
                }
                Ok(()) => state.propose(&v, peer),
            },
        }
    };
    if r["ok"] == false {
        use crate::audit::Field as F;
        let mut extra = vec![(
            F::Reason,
            r["code"].as_str().unwrap_or("INTERNAL_ERROR").into(),
        )];
        if let Some(peer) = peer_credentials_snapshot {
            extra.push((F::PeerUid, peer.uid.to_string()));
            extra.push((F::PeerPid, peer.pid.to_string()));
        }
        if let Some(request) = v["challenge_id"]
            .as_str()
            .and_then(|id| state.pending.get(id))
            .filter(|req| v["request_digest"] == req.digest)
        {
            audit_request(request, "REQUEST_REJECTED", &extra);
        } else {
            crate::audit::emit("REQUEST_REJECTED", &extra);
        }
    }
    /*AUTH DISPATCH*/
    let execution = if !approval && message_type == "CONSUME_APPROVED" && r["status"] == "CONSUMED"
    {
        v.get("challenge_id")
            .and_then(Value::as_str)
            .and_then(|id| state.pending.get(id))
            .and_then(|request| {
                request
                    .ops
                    .first()
                    .filter(|op| op["type"] == "exec")
                    .map(|op| {
                        (
                            request.challenge.clone(),
                            op.clone(),
                            request_audit_fields(request),
                        )
                    })
            })
    } else {
        None
    };
    if let Some(m) = r.as_object_mut() {
        m.insert(
            "broker_instance_id".into(),
            Value::String(state.instance.clone()),
        );
        m.insert(
            "response_to".into(),
            v.get("type").cloned().unwrap_or(Value::Null),
        );
        for key in ["challenge_id", "request_digest", "view_id"] {
            if !m.contains_key(key) {
                if let Some(x) = v.get(key) {
                    m.insert(key.into(), x.clone());
                }
            }
        }
    }
    if execution.is_some() {
        if let Some(id) = v["challenge_id"].as_str() {
            state
                .synchronous_executions
                .insert(id.to_owned(), ExecutionPhase::Dispatching);
        }
        if let Some(request) = v["challenge_id"]
            .as_str()
            .and_then(|id| state.pending.get_mut(id))
        {
            request.execution_phase = ExecutionPhase::Dispatching;
        }
    }
    drop(state);
    if let Some((challenge, operation, mut fields)) = execution {
        use crate::audit::Field as F;
        fields.push((F::ExecutionId, challenge[..32].into()));
        crate::audit::emit("EXECUTION_DISPATCH_STARTED", &fields);
        let notify_started = || {
            if let Ok(mut state) = broker.lock() {
                if let Some(phase) = state.synchronous_executions.get_mut(&challenge) {
                    *phase = ExecutionPhase::Started;
                }
                if let Some(r) = state.pending.get_mut(&challenge) {
                    if r.execution_phase == ExecutionPhase::Dispatching {
                        r.execution_phase = ExecutionPhase::Started;
                    }
                }
            }
        };
        let instance = fields
            .iter()
            .find(|(k, _)| *k == F::BrokerInstanceId)
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let (outcome, audit_completed) =
            call_privileged_executor(&challenge, &operation, notify_started, instance);
        if let Ok(mut state) = broker.lock() {
            state.synchronous_executions.remove(&challenge);
            if let Some(r) = state.pending.get_mut(&challenge) {
                r.execution_phase = ExecutionPhase::Finished;
            }
        }
        fields.retain(|(key, _)| *key != F::State);
        if let Some(value) = outcome["execution"].as_str() {
            fields.push((F::State, value.into()));
        }
        if let Some(value) = outcome["exit_code"].as_i64() {
            fields.push((F::ChildExitStatus, value.to_string()));
        }
        fields.push((
            F::Result,
            match outcome["execution"].as_str() {
                Some("SUCCEEDED") => 0,
                Some("FAILED") => 14,
                Some("INTERNAL_ERROR") => 15,
                _ => 16,
            }
            .to_string(),
        ));
        crate::audit::emit(
            broker_execution_event(
                false,
                outcome["execution"].as_str().unwrap_or("UNKNOWN"),
                audit_completed,
            ),
            &fields,
        );
        if let Some(response) = r.as_object_mut() {
            for (key, value) in outcome.as_object().into_iter().flat_map(|map| map.iter()) {
                response.insert(key.clone(), value.clone());
            }
            response.insert(
                "mayi_exit_code".into(),
                Value::from(match outcome["execution"].as_str() {
                    Some("SUCCEEDED") => 0,
                    Some("FAILED") => 14,
                    Some("INTERNAL_ERROR") => 15,
                    _ => 16,
                }),
            );
        }
    } else if !approval && message_type == "CONSUME_APPROVED" && r["status"] == "CONSUMED" {
        r["execution"] = Value::String("EXECUTION_DISABLED".into());
    }
    let out = r.to_string();
    if out.len() > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broker response exceeds frame limit",
        ));
    }
    let response_deadline = Instant::now() + Duration::from_secs(5);
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(&(out.len() as u32).to_be_bytes())?;
    write_all_deadline(&mut s, out.as_bytes(), response_deadline)
}
fn dispatch(
    stream: UnixStream,
    broker: Arc<Mutex<Broker>>,
    approval: bool,
    request_gid: u32,
    approval_gid: u32,
    active: Arc<AtomicUsize>,
) {
    if active
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < WORKERS).then_some(n + 1)
        })
        .is_err()
    {
        return;
    }
    let role = if approval { "approval" } else { "request" };
    let worker_active = active.clone();
    if let Err(e) = std::thread::Builder::new()
        .name(format!("mayi-{role}"))
        .spawn(move || {
            if let Err(e) = handle(stream, &broker, approval, request_gid, approval_gid) {
                crate::audit::emit(
                    "CONNECTION_ERROR",
                    &[
                        (crate::audit::Field::Role, role.into()),
                        (crate::audit::Field::Reason, e.kind().to_string()),
                    ],
                );
            }
            worker_active.fetch_sub(1, Ordering::Release);
        })
    {
        active.fetch_sub(1, Ordering::Release);
        crate::audit::emit(
            "CONNECTION_REJECTED",
            &[
                (crate::audit::Field::Role, role.into()),
                (
                    crate::audit::Field::Reason,
                    format!("worker_spawn_failed: {}", e.kind()),
                ),
            ],
        );
    }
}

pub fn serve(
    request_path: PathBuf,
    approval_path: PathBuf,
    request_gid: u32,
    approval_gid: u32,
    development_shared_role_group: bool,
) -> io::Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REAL_ROOT_DISABLED",
        ));
    }
    if !development_shared_role_group && request_gid == approval_gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "production request and approval socket groups must differ",
        ));
    }
    if request_path == approval_path {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "request and approval sockets must differ",
        ));
    }
    unsafe {
        libc::umask(0o077);
    }
    let _instance_lock = super::broker_instance_lock(&request_path)?;
    let request_socket_path = super::secure_socket_path(&request_path)?;
    let approval_socket_path = super::secure_socket_path(&approval_path)?;
    super::install_broker_shutdown_handlers();
    let mut state = Broker::new()?;
    // Existing explicit standalone-development mode must not read or repair the
    // production-owned key. Broker::new already generated an ephemeral key;
    // production services never pass this flag and retain the strict disk key.
    if !development_shared_role_group {
        state.request_id_key =
            crate::request_ids::load_key(std::path::Path::new("/var/lib/mayi-broker"))?;
    }
    let broker = Arc::new(Mutex::new(state));
    let request_active = Arc::new(AtomicUsize::new(0));
    let approval_active = Arc::new(AtomicUsize::new(0));
    let (req, req_metadata) = super::listener_for(&request_path, request_gid)?;
    let (auth, auth_metadata) = match super::listener_for(&approval_path, approval_gid) {
        Ok(listener) => listener,
        Err(error) => {
            drop(req);
            let _ = super::remove_broker_socket_if_same(
                &request_socket_path,
                &req_metadata,
                unsafe { libc::geteuid() },
                request_gid,
            );
            return Err(error);
        }
    };
    req.set_nonblocking(true)?;
    auth.set_nonblocking(true)?;
    let instance = broker
        .lock()
        .map_err(|_| io::Error::other("broker state poisoned"))?
        .instance
        .clone();
    crate::audit::emit(
        "BROKER_STARTED",
        &[(crate::audit::Field::BrokerInstanceId, instance)],
    );
    while !super::broker_shutdown_requested() {
        let mut activity = false;
        match req.accept() {
            Ok((s, _)) => {
                activity = true;
                dispatch(
                    s,
                    broker.clone(),
                    false,
                    request_gid,
                    approval_gid,
                    request_active.clone(),
                )
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        match auth.accept() {
            Ok((s, _)) => {
                activity = true;
                dispatch(
                    s,
                    broker.clone(),
                    true,
                    request_gid,
                    approval_gid,
                    approval_active.clone(),
                )
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        run_queue_scheduler(&broker);
        if !activity {
            std::thread::sleep(Duration::from_millis(100))
        }
    }
    let records = broker
        .lock()
        .map_err(|_| io::Error::other("broker state poisoned"))?
        .begin_stopping();
    for (event, fields) in records {
        crate::audit::emit(event, &fields);
    }
    drop(req);
    drop(auth);
    super::remove_broker_socket_if_same(
        &request_socket_path,
        &req_metadata,
        unsafe { libc::geteuid() },
        request_gid,
    )?;
    super::remove_broker_socket_if_same(
        &approval_socket_path,
        &auth_metadata,
        unsafe { libc::geteuid() },
        approval_gid,
    )?;
    Ok(())
}
#[cfg(test)]
#[path = "broker_deadline_tests.rs"]
mod deadline_regressions;

#[cfg(test)]
#[path = "broker_audit_tests.rs"]
mod audit_regressions;
#[cfg(test)]
#[path = "broker_security_tests.rs"]
mod security_regressions;

#[cfg(test)]
mod tests {
    fn denied() -> Result<(), serde_json::Value> {
        Err(serde_json::json!({"ok": false, "code": "DENIED"}))
    }

    #[test]
    fn approval_gate_requires_every_step_and_never_overrides_failure() {
        use super::approval_authorization_gate;
        use std::cell::Cell;

        for initial in [false, true] {
            let preflight_called = Cell::new(false);
            let pam_called = Cell::new(false);
            let final_called = Cell::new(false);
            let result = approval_authorization_gate(
                if initial { Ok(()) } else { denied() },
                || {
                    preflight_called.set(true);
                    Ok(())
                },
                || {
                    pam_called.set(true);
                    Ok(true)
                },
                || {
                    final_called.set(true);
                    Ok(())
                },
            );
            assert_eq!(result.is_ok(), initial);
            assert_eq!(preflight_called.get(), initial);
            assert_eq!(pam_called.get(), initial);
            assert_eq!(final_called.get(), initial);
        }

        for initial_error in [false, true] {
            let pam_called = Cell::new(false);
            let result = approval_authorization_gate(
                if initial_error {
                    Err(serde_json::json!({"code":"NSS_ERROR"}))
                } else {
                    denied()
                },
                || Ok(()),
                || {
                    pam_called.set(true);
                    Ok(true)
                },
                || Ok(()),
            );
            assert!(result.is_err());
            assert!(
                !pam_called.get(),
                "initial authorization failure must stop before PAM"
            );
        }

        for pam_result in [
            Err(serde_json::json!({"code":"PAM_UNAVAILABLE"})),
            Ok(false),
        ] {
            let final_called = Cell::new(false);
            let result = approval_authorization_gate(
                Ok(()),
                || Ok(()),
                || pam_result.clone(),
                || {
                    final_called.set(true);
                    Ok(())
                },
            );
            assert!(result.is_err());
            assert!(!final_called.get());
        }

        for final_result in [denied(), Err(serde_json::json!({"code":"NSS_ERROR"}))] {
            assert!(approval_authorization_gate(
                Ok(()),
                || Ok(()),
                || Ok(true),
                || final_result.clone()
            )
            .is_err());
        }
    }
    use super::*;
    fn broker() -> Broker {
        Broker::new().unwrap()
    }
    fn proposal() -> Value {
        exec_proposal(json!(["printf", "x"]))
    }
    fn exec_proposal(argv: Value) -> Value {
        json!({"type":"PROPOSE_REQUEST","protocol":5,"target":{"uid":1000,"gid":1000},"operations":[{"type":"exec","executable":"/usr/bin/printf","argv":argv}]})
    }
    fn queue_proposal(dependencies: Vec<String>) -> Value {
        json!({"type":"QUEUE_REQUEST","protocol":5,"target":{"uid":1000,"gid":1000},"dependencies":dependencies,"operations":[{"type":"exec","executable":"/usr/bin/true","argv":["true"]}]})
    }
    fn view_as(b: &mut Broker, p: &Value, approver_uid: u32) -> Value {
        b.authority(&json!({"type":"GET_CHALLENGE","protocol":5,"broker_instance_id":p["broker_instance_id"],"challenge_id":p["challenge_id"]}),approver_uid)
    }
    fn view(b: &mut Broker, p: &Value) -> Value {
        view_as(b, p, 9001)
    }
    fn decision(p: &Value, v: &Value, ty: &str) -> Value {
        json!({"type":ty,"protocol":5,"broker_instance_id":p["broker_instance_id"],"challenge_id":p["challenge_id"],"request_digest":p["request_digest"],"view_id":v["view_id"]})
    }
    fn consume(p: &Value) -> Value {
        json!({"type":"CONSUME_APPROVED","protocol":5,"broker_instance_id":p["broker_instance_id"],"challenge_id":p["challenge_id"],"request_digest":p["request_digest"]})
    }
    #[test]
    fn approval_transport_passes_one_cloexec_descriptor_with_the_frame() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let terminal = fs::File::open("/dev/null").unwrap();
        let message = json!({"type":"APPROVE_CHALLENGE","protocol":5});
        let deadline = Instant::now() + Duration::from_secs(2);
        send_frame_with_fd(&mut sender, &message, terminal.as_raw_fd(), deadline).unwrap();
        let (body, received_fd) = read_frame_with_fd(&mut receiver, deadline).unwrap();
        let fd = received_fd.expect("SCM_RIGHTS descriptor was lost");
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), message);
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
    }
    #[test]
    fn approval_transport_rejects_descriptors_after_the_frame_header() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let body = br#"{"type":"APPROVE_CHALLENGE"}"#;
        sender
            .write_all(&(body.len() as u32).to_be_bytes())
            .unwrap();
        let terminal = fs::File::open("/dev/null").unwrap();
        send_frame_with_fd(
            &mut sender,
            &json!({"body":"extra"}),
            terminal.as_raw_fd(),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        let result = read_frame_with_fd(&mut receiver, Instant::now() + Duration::from_secs(2));
        assert!(result.is_err());
    }
    #[test]
    fn approval_console_preserves_broker_authorization_errors() {
        let error = check_authority_response(&json!({"ok":false,"code":"UNAUTHORIZED_APPROVER","message":"peer UID 1001 is not a member of configured approver group GID 23013"})).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("MAYI_UNAUTHORIZED_APPROVER"));
        assert!(!error.to_string().contains("miscorrelated"));
    }

    #[test]
    fn nss_group_lookup_handles_primary_supplementary_and_missing_accounts() {
        let uid = unsafe { libc::geteuid() };
        let primary_gid = unsafe { libc::getegid() };
        assert_eq!(uid_in_group(uid, primary_gid).unwrap(), Some(true));

        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        assert!(count >= 0);
        if count > 1 {
            let mut groups = vec![0 as libc::gid_t; count as usize];
            let actual = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
            assert!(actual > 0);
            if let Some(group) = groups[..actual as usize]
                .iter()
                .find(|group| **group != primary_gid)
            {
                assert_eq!(uid_in_group(uid, *group).unwrap(), Some(true));
            }
        }
        assert_eq!(uid_in_group(u32::MAX, primary_gid).unwrap(), None);
    }
    #[test]
    fn queued_requests_have_unique_broker_ids_and_are_requester_bound() {
        let mut b = broker();
        let first = b.propose(&queue_proposal(vec![]), 1001);
        let second = b.propose(&queue_proposal(vec![]), 1001);
        assert_eq!(first["type"], "QUEUE_RESPONSE");
        let first_id = first["request_id"].as_str().unwrap();
        let second_id = second["request_id"].as_str().unwrap();
        assert!(valid_request_id(first_id) && valid_request_id(second_id));
        assert_ne!(first_id, second_id);
        assert_ne!(first_id, first["request_digest"].as_str().unwrap());
        let status = b.queue_status_request(
            &json!({"type":"GET_QUEUE_STATUS","protocol":5,"request_id":first_id}),
            1001,
        );
        assert_eq!(status["state"], "PENDING_APPROVAL");
        assert_eq!(
            b.queue_status_request(
                &json!({"type":"GET_QUEUE_STATUS","protocol":5,"request_id":first_id}),
                1002
            )["code"],
            "UNAUTHORIZED_REQUESTER"
        );
        assert_eq!(
            b.propose(&queue_proposal(vec![first_id.to_owned()]), 1002)["code"],
            "DEPENDENCY_OWNER_MISMATCH"
        );
        assert_eq!(
            b.propose(
                &queue_proposal(vec!["rq_00000000000000000000000000000000".into()]),
                1001
            )["code"],
            "DEPENDENCY_NOT_FOUND"
        );
        let dependent = b.propose(&queue_proposal(vec![first_id.to_owned()]), 1001);
        let stored = b
            .pending
            .values()
            .find(|r| r.request_id.as_deref() == dependent["request_id"].as_str())
            .unwrap();
        assert_eq!(stored.dependencies, vec![first_id]);
        assert_eq!(stored.requester, 1001);
    }

    #[test]
    fn queue_dependency_cycles_are_rejected_and_failed_parents_block_children() {
        let mut b = broker();
        let parent = b.propose(&queue_proposal(vec![]), 1001);
        let parent_id = parent["request_id"].as_str().unwrap().to_owned();
        let child = b.propose(&queue_proposal(vec![parent_id.clone()]), 1001);
        let child_id = child["request_id"].as_str().unwrap().to_owned();
        b.pending
            .get_mut(parent["challenge_id"].as_str().unwrap())
            .unwrap()
            .dependencies
            .push(child_id.clone());
        assert!(!b.dependency_graph_acyclic(&child_id, std::slice::from_ref(&parent_id)));
        b.pending
            .get_mut(parent["challenge_id"].as_str().unwrap())
            .unwrap()
            .dependencies
            .clear();
        for proposal in [&parent, &child] {
            let view = view(&mut b, proposal);
            let approved = b.authority(&decision(proposal, &view, "APPROVE_CHALLENGE"), 9001);
            assert_eq!(approved["status"], "APPROVED");
        }
        let parent_challenge = parent["challenge_id"].as_str().unwrap();
        let failed = b.pending.get_mut(parent_challenge).unwrap();
        failed.queue_state = Some(QueueState::Failed);
        failed.state = State::Consumed;
        failed.mayi_result = Some(14);
        let shared = Arc::new(Mutex::new(b));
        run_queue_scheduler(&shared);
        let status = shared.lock().unwrap().queue_status_request(
            &json!({"type":"GET_QUEUE_STATUS","protocol":5,"request_id":child_id}),
            1001,
        );
        assert_eq!(status["state"], "BLOCKED");
        assert_eq!(status["blocking_dependency"], parent_id);
    }

    #[test]
    fn proposal_stores_the_authenticated_requester_uid() {
        let mut b = broker();
        let p = b.propose(&proposal(), 1001);
        assert_eq!(p["status"], "PENDING_APPROVAL");
        assert_eq!(
            b.pending[p["challenge_id"].as_str().unwrap()].requester,
            1001
        );
        assert_eq!(
            b.authority(&json!({"type":"APPROVE_CHALLENGE","protocol":5}), 1000)["code"],
            "BROKER_INSTANCE_MISMATCH"
        );
    }

    #[test]
    fn group_authorized_requesters_still_cannot_consume_each_others_requests() {
        let mut b = broker();
        let p = b.propose(&proposal(), 1001);
        let v = view_as(&mut b, &p, 1000);
        assert_eq!(
            b.authority(&decision(&p, &v, "APPROVE_CHALLENGE"), 1000)["status"],
            "APPROVED"
        );
        assert_eq!(b.views[v["view_id"].as_str().unwrap()].approver_uid, 1000);
        assert_eq!(
            b.consume_request(&consume(&p), 1000)["code"],
            "UNAUTHORIZED_REQUESTER"
        );
        assert_eq!(b.consume_request(&consume(&p), 1001)["status"], "CONSUMED");
    }
    #[test]
    fn exact_exec_is_rendered_and_status_is_requester_bound() {
        let mut b = broker();
        let p = b.propose(
            &exec_proposal(json!(["printf", "%s", "; touch /tmp/pwned"])),
            1000,
        );
        assert_eq!(p["status"], "PENDING_APPROVAL");
        let v = view(&mut b, &p);
        let rendered = v["rendered"].as_str().unwrap();
        assert!(rendered.contains("Executor identity: UID 0, primary GID 23012"));
        assert!(rendered.contains("Request target UID/GID (metadata only): 1000/1000"));
        assert!(rendered.contains("Executable:\n\"/usr/bin/printf\""));
        assert!(rendered.contains("[0] \"printf\""));
        assert!(rendered.contains("[2] \"; touch /tmp/pwned\""));
        let status = json!({"type":"GET_REQUEST_STATUS","protocol":5,"broker_instance_id":p["broker_instance_id"],"challenge_id":p["challenge_id"],"request_digest":p["request_digest"]});
        assert_eq!(b.status_request(&status, 1000)["status"], "PENDING");
        assert_eq!(
            b.status_request(&status, 1001)["code"],
            "UNAUTHORIZED_REQUESTER"
        );
        assert_eq!(
            b.authority(&decision(&p, &v, "APPROVE_CHALLENGE"), 9001)["status"],
            "APPROVED"
        );
        assert_eq!(b.status_request(&status, 1000)["status"], "APPROVED");
    }
    #[test]
    fn approval_is_one_shot_and_executor_handoff_is_deferred_to_network_handler() {
        let mut b = broker();
        let p = b.propose(&proposal(), 1000);
        let base = p.clone();
        let v = view(&mut b, &p);
        assert_eq!(v["status"], "DISPLAYED");
        let approve = decision(&p, &v, "APPROVE_CHALLENGE");
        assert_eq!(b.authority(&approve, 9001)["status"], "APPROVED");
        assert_eq!(b.authority(&approve, 9001)["code"], "VIEW_ALREADY_USED");
        let consume = consume(&base);
        let consumed = b.consume_request(&consume, 1000);
        assert_eq!(consumed["state"], "CONSUMED");
        assert_eq!(consumed["execution"], "EXECUTION_PENDING");
        assert_eq!(
            b.consume_request(&consume, 1000)["code"],
            "ALREADY_CONSUMED"
        );
        assert_eq!(b.authority(&consume, 9001)["code"], "INVALID_MESSAGE_TYPE");
    }
    #[test]
    fn deny_and_explain_cannot_be_approved() {
        let mut b = broker();
        let p = b.propose(&proposal(), 1000);
        let v = view(&mut b, &p);
        let deny = decision(&p, &v, "DENY_CHALLENGE");
        assert_eq!(b.authority(&deny, 9001)["status"], "DENIED");
        assert_eq!(b.authority(&deny, 9001)["code"], "VIEW_ALREADY_USED");
        assert_eq!(
            b.consume_request(&consume(&p), 1000)["code"],
            "INVALID_STATE_TRANSITION"
        );
        let p = b.propose(&proposal(), 1000);
        let v1 = view(&mut b, &p);
        let explain = decision(&p, &v1, "EXPLAIN_CHALLENGE");
        assert_eq!(b.authority(&explain, 9001)["authorized"], false);
        assert_eq!(
            b.pending[p["challenge_id"].as_str().unwrap()].state,
            State::Explained
        );
        assert_eq!(b.authority(&explain, 9001)["code"], "VIEW_ALREADY_USED");
        assert_eq!(
            b.status_request(&json!({"type":"GET_REQUEST_STATUS","protocol":5,"broker_instance_id":p["broker_instance_id"],"challenge_id":p["challenge_id"],"request_digest":p["request_digest"]}),1000)["status"],
            "EXPLAINED"
        );
        let mut changed = proposal();
        changed["operations"][0]["argv"] = json!(["printf", "changed"]);
        let replacement = b.propose(&changed, 1000);
        assert_ne!(replacement["challenge_id"], p["challenge_id"]);
        assert_eq!(replacement["status"], "PENDING_APPROVAL");
    }
    #[test]
    fn views_are_one_shot_replaceable_and_not_in_proposals() {
        let mut b = broker();
        let p = b.propose(&proposal(), 1000);
        assert!(p.get("view_id").is_none());
        let v1 = view(&mut b, &p);
        let v2 = view(&mut b, &p);
        assert_ne!(v1["view_id"], v2["view_id"]);
        let stale = decision(&p, &v1, "APPROVE_CHALLENGE");
        assert_eq!(b.authority(&stale, 9001)["code"], "VIEW_NOT_FOUND");
        let mut fake_dec = decision(&p, &v2, "APPROVE_CHALLENGE");
        fake_dec["view_id"] = json!(hex::encode([0xa5u8; 24]));
        assert_eq!(b.authority(&fake_dec, 9001)["code"], "VIEW_NOT_FOUND");
        assert_eq!(
            b.pending[p["challenge_id"].as_str().unwrap()].state,
            State::Pending
        );
        assert_eq!(
            b.authority(&decision(&p, &v2, "APPROVE_CHALLENGE"), 9001)["status"],
            "APPROVED"
        );
    }
    #[test]
    fn requester_pending_limit_is_bounded() {
        let mut b = broker();
        for _ in 0..MAX_PENDING_PER_REQUESTER {
            assert_eq!(b.propose(&proposal(), 1000)["status"], "PENDING_APPROVAL")
        }
        assert_eq!(
            b.propose(&proposal(), 1000)["code"],
            "TOO_MANY_PENDING_REQUESTS"
        );
        assert_eq!(b.pending.len(), MAX_PENDING_PER_REQUESTER);
    }
    #[test]
    fn view_expires_independently() {
        let mut b = broker();
        let p = b.propose(&proposal(), 1000);
        let v = view(&mut b, &p);
        let id = v["view_id"].as_str().unwrap().to_owned();
        b.views.get_mut(&id).unwrap().deadline = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            b.authority(&decision(&p, &v, "APPROVE_CHALLENGE"), 9001)["code"],
            "VIEW_EXPIRED"
        );
        assert_eq!(
            b.pending[p["challenge_id"].as_str().unwrap()].state,
            State::Pending
        );
    }
    #[test]
    fn concurrent_approve_and_deny_have_one_terminal_winner() {
        use std::sync::{Arc, Mutex};
        let mut b = broker();
        let p = b.propose(&proposal(), 1000);
        let v = view(&mut b, &p);
        let approve = decision(&p, &v, "APPROVE_CHALLENGE");
        let deny = decision(&p, &v, "DENY_CHALLENGE");
        let b = Arc::new(Mutex::new(b));
        let mut joins = Vec::new();
        for m in [approve, deny] {
            let b = b.clone();
            joins.push(std::thread::spawn(move || {
                b.lock().unwrap().authority(&m, 9001)
            }))
        }
        let out: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
        assert_eq!(
            out.iter()
                .filter(|x| x["status"] == "APPROVED" || x["status"] == "DENIED")
                .count(),
            1
        );
        assert_eq!(
            out.iter()
                .filter(|x| x["code"] == "VIEW_ALREADY_USED")
                .count(),
            1
        );
        assert!(matches!(
            b.lock().unwrap().pending[p["challenge_id"].as_str().unwrap()].state,
            State::Approved | State::Denied
        ));
    }
    #[test]
    fn same_uid_socket_substitution_cannot_reuse_real_view() {
        let mut b = broker();
        let p = b.propose(&proposal(), 1000);
        let real = view(&mut b, &p);
        let decoy = json!({"view_id":hex::encode([0xa5u8;24]),"broker_instance_id":p["broker_instance_id"],"challenge_id":p["challenge_id"],"request_digest":p["request_digest"],"state":"PENDING_APPROVAL","rendered":"DECOY: approve /attacker"});
        let forged = decision(&p, &decoy, "APPROVE_CHALLENGE");
        assert_eq!(b.authority(&forged, 9001)["code"], "VIEW_NOT_FOUND");
        assert_eq!(
            b.pending[p["challenge_id"].as_str().unwrap()].state,
            State::Pending
        );
        assert_eq!(
            b.authority(&decision(&p, &real, "APPROVE_CHALLENGE"), 9001)["status"],
            "APPROVED"
        );
    }
    #[test]
    fn wrong_approver_cannot_use_view() {
        let mut b = broker();
        let p = b.propose(&proposal(), 1000);
        let v = view(&mut b, &p);
        assert_eq!(
            b.authority(&decision(&p, &v, "APPROVE_CHALLENGE"), 9002)["code"],
            "VIEW_BINDING_MISMATCH"
        );
        assert_eq!(
            b.pending[p["challenge_id"].as_str().unwrap()].state,
            State::Pending
        );
    }
    #[test]
    fn restart_changes_instance() {
        let a = broker();
        let b = broker();
        assert_ne!(a.instance, b.instance)
    }
    #[test]
    fn invalid_state_transitions_fail() {
        for (from, to) in [
            (State::Denied, State::Approved),
            (State::Expired, State::Approved),
            (State::Consumed, State::Approved),
            (State::Consumed, State::Consumed),
            (State::Consumed, State::Pending),
        ] {
            let mut s = from;
            assert!(transition(&mut s, to).is_err());
        }
        let mut s = State::Proposed;
        assert!(transition(&mut s, State::Pending).is_ok());
    }
    #[test]
    fn client_cannot_supply_approval_or_change_approved_object() {
        let mut b = broker();
        for key in ["approved", "approval", "decision", "scope", "consumed"] {
            let mut forged = proposal();
            let value = if key == "approval" {
                json!({"scope":"once","digest":"ab".repeat(32)})
            } else {
                json!("once")
            };
            forged.as_object_mut().unwrap().insert(key.into(), value);
            assert_eq!(b.propose(&forged, 1000)["code"], "INVALID_PROTOCOL");
        }
        assert!(b.pending.is_empty());
        let p = b.propose(&proposal(), 1000);
        let v = view(&mut b, &p);
        let mut dec = decision(&p, &v, "APPROVE_CHALLENGE");
        assert_eq!(b.authority(&dec, 9001)["status"], "APPROVED");
        dec["path"] = Value::String("/attacker".into());
        assert_eq!(b.authority(&dec, 9001)["code"], "UNKNOWN_FIELD");
        assert_eq!(
            b.pending[p["challenge_id"].as_str().unwrap()].ops[0]["executable"],
            "/usr/bin/printf"
        );
    }
    #[test]
    fn restart_invalidates_approved_challenge() {
        let mut a = broker();
        let p = a.propose(&proposal(), 1000);
        let v = view(&mut a, &p);
        let dec = decision(&p, &v, "APPROVE_CHALLENGE");
        assert_eq!(a.authority(&dec, 9001)["status"], "APPROVED");
        let mut b = broker();
        assert_ne!(a.instance, b.instance);
        assert_eq!(b.authority(&dec, 9001)["code"], "BROKER_INSTANCE_MISMATCH");
        assert_eq!(
            b.consume_request(&consume(&p), 1000)["code"],
            "BROKER_INSTANCE_MISMATCH"
        );
    }
    #[test]
    fn challenge_and_digest_substitution_rejected() {
        let mut b = broker();
        let a = b.propose(&proposal(), 1000);
        let c = b.propose(&proposal(), 1000);
        assert_ne!(a["challenge_id"], c["challenge_id"]);
        let v = view(&mut b, &a);
        let sub = decision(&c, &v, "APPROVE_CHALLENGE");
        assert_eq!(b.authority(&sub, 9001)["code"], "VIEW_BINDING_MISMATCH");
        let mut bad = decision(&a, &v, "APPROVE_CHALLENGE");
        bad["request_digest"] = json!("00".repeat(32));
        assert_eq!(b.authority(&bad, 9001)["code"], "VIEW_BINDING_MISMATCH");
        let mut wrong_instance = decision(&a, &v, "APPROVE_CHALLENGE");
        wrong_instance["broker_instance_id"] = json!("00".repeat(24));
        assert_eq!(
            b.authority(&wrong_instance, 9001)["code"],
            "BROKER_INSTANCE_MISMATCH"
        );
    }
    #[test]
    fn expiry_and_substitution_rejected() {
        let mut b = broker();
        let p = b.propose(&proposal(), 1000);
        let v = view(&mut b, &p);
        let id = p["challenge_id"].as_str().unwrap().to_owned();
        b.pending.get_mut(&id).unwrap().deadline = Instant::now() - Duration::from_secs(1);
        let dec = decision(&p, &v, "APPROVE_CHALLENGE");
        assert_eq!(b.authority(&dec, 9001)["code"], "VIEW_EXPIRED");
        let p = b.propose(&proposal(), 1000);
        let id = p["challenge_id"].as_str().unwrap().to_owned();
        let v = view(&mut b, &p);
        let approve = decision(&p, &v, "APPROVE_CHALLENGE");
        assert_eq!(b.authority(&approve, 9001)["status"], "APPROVED");
        b.pending.get_mut(&id).unwrap().deadline = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            b.consume_request(&consume(&p), 1000)["code"],
            "REQUEST_EXPIRED"
        );
        let p = b.propose(&proposal(), 1000);
        let wrong = json!({"type":"GET_CHALLENGE","protocol":5,"broker_instance_id":p["broker_instance_id"],"challenge_id":p["challenge_id"],"description":"forged"});
        assert_eq!(
            b.authority(&wrong, 9001)["code"],
            "BROKER_INSTANCE_MISMATCH"
        );
    }
    #[test]
    fn concurrent_consume_is_atomic() {
        use std::sync::{Arc, Mutex};
        let mut b = broker();
        let p = b.propose(&proposal(), 1000);
        let id = p["challenge_id"].as_str().unwrap().to_owned();
        let dg = p["request_digest"].as_str().unwrap().to_owned();
        let inst = p["broker_instance_id"].as_str().unwrap().to_owned();
        let v = view(&mut b, &p);
        let dec = decision(&p, &v, "APPROVE_CHALLENGE");
        b.authority(&dec, 9001);
        let b = Arc::new(Mutex::new(b));
        let mut joins = Vec::new();
        for _ in 0..2 {
            let b = b.clone();
            let id = id.clone();
            let dg = dg.clone();
            let inst = inst.clone();
            joins.push(std::thread::spawn(move || {
                b.lock().unwrap().consume_request(&json!({"type":"CONSUME_APPROVED","protocol":5,"broker_instance_id":inst,"challenge_id":id,"request_digest":dg}),1000)
            }));
        }
        let out: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
        assert_eq!(out.iter().filter(|v| v["status"] == "CONSUMED").count(), 1);
        assert_eq!(
            out.iter()
                .filter(|v| v["code"] == "ALREADY_CONSUMED")
                .count(),
            1
        );
    }
    #[test]
    fn console_decision_grammar_is_exact() {
        assert_eq!(parse_decision(b"y"), Some("APPROVE_CHALLENGE"));
        assert_eq!(parse_decision(b"n"), Some("DENY_CHALLENGE"));
        assert_eq!(parse_decision(b"e"), Some("EXPLAIN_CHALLENGE"));
        assert_eq!(parse_decision(b"approve"), Some("APPROVE_CHALLENGE"));
        assert_eq!(parse_decision(b"deny"), Some("DENY_CHALLENGE"));
        assert_eq!(parse_decision(b"explain"), Some("EXPLAIN_CHALLENGE"));
        for invalid in [
            b"approve\nextra".as_slice(),
            b"approve\n",
            b"approve\n\n",
            b"approve extra",
            b" approve",
            b"approve ",
            b"approve\t",
            b"approve\rjunk",
            "apprové".as_bytes(),
            "аpprove".as_bytes(),
            b"",
        ] {
            assert_eq!(parse_decision(invalid), None, "accepted {invalid:?}");
        }
    }
    #[test]
    fn console_commands_use_readable_unambiguous_argv_rendering() {
        assert_eq!(render_console_arg("systemctl"), "systemctl");
        assert_eq!(render_console_arg("hello world"), "'hello world'");
        assert_eq!(render_console_arg("$HOME"), "'$HOME'");
        assert_eq!(
            render_console_arg("; touch /tmp/pwned"),
            "'; touch /tmp/pwned'"
        );
        assert_eq!(render_console_arg("C:\\tmp\\x"), "'C:\\tmp\\x'");
        assert_eq!(render_console_arg("can't"), "\"can't\"");
        assert_eq!(render_console_arg("line\nfeed"), "\"line\\nfeed\"");

        let rows = vec![json!({
            "request_id":"request-1", "queue_state":"PENDING_APPROVAL",
            "requester_uid":1001, "dependencies":[], "operations":[{
                "type":"exec", "executable":"/usr/bin/foo",
                "argv":["foo", "hello world", "$HOME", "; touch /tmp/pwned"]
            }]
        })];
        let rendered = approval_ui::render(&rows, &[0], false, 0, 100, 100).0;
        assert!(rendered.contains("[Space] More information"));
        assert!(!rendered.contains("request ID:"));
        let expanded = approval_ui::render(&rows, &[0], true, 0, 100, 100).0;
        assert!(expanded.contains("[Space] Less information"));
        assert!(expanded.contains("request_id"));
        assert!(rendered.contains("foo 'hello world'"));
        assert!(expanded.contains("hello world"));
        assert!(expanded.contains("$HOME"));
        assert!(expanded.contains("; touch /tmp/pwned"));
        assert!(rendered.contains("Requested by UID 1001"));
        assert!(!rendered.contains("argv[1]"));
        assert!(!rendered.contains("\nfeed"));
    }

    #[test]
    fn visible_clear_requires_tty_and_a_usable_terminal_type() {
        assert!(terminal_supports_visible_clear(
            true,
            Some("xterm-256color")
        ));
        assert!(!terminal_supports_visible_clear(
            false,
            Some("xterm-256color")
        ));
        assert!(!terminal_supports_visible_clear(true, None));
        assert!(!terminal_supports_visible_clear(true, Some("")));
        assert!(!terminal_supports_visible_clear(true, Some("dumb")));
        assert!(!terminal_supports_visible_clear(true, Some("unknown")));
        assert!(!terminal_supports_visible_clear(true, Some("vt52")));
        assert!(terminal_supports_visible_clear(true, Some("vt100")));
    }

    #[test]
    fn successful_decisions_clear_only_the_visible_screen_and_failures_do_not() {
        for (decision, acknowledgement) in [
            ("approve", "Approved: 0"),
            ("deny", "Denied: 0"),
            ("explain", "Follow-up requested: 0"),
        ] {
            let mut output = Vec::new();
            write_console_decision_feedback(&mut output, decision, &[0], false, true).unwrap();
            assert!(output.starts_with(CLEAR_VISIBLE_SCREEN));
            assert!(output.ends_with(format!("{acknowledgement}\n").as_bytes()));
            assert!(!output.windows(4).any(|window| window == b"\x1b[3J"));
        }
        let mut no_decision = Vec::new();
        write_console_decision_feedback(&mut no_decision, "approve", &[], true, true).unwrap();
        assert!(no_decision.is_empty());
        let mut rejected = Vec::new();
        write_console_decision_feedback(&mut rejected, "approve", &[0], true, true).unwrap();
        assert!(!rejected
            .windows(CLEAR_VISIBLE_SCREEN.len())
            .any(|window| window == CLEAR_VISIBLE_SCREEN));
        assert!(rejected.ends_with(b"Approved: 0\n"));
        let mut redirected = Vec::new();
        write_console_decision_feedback(&mut redirected, "deny", &[0], false, false).unwrap();
        assert!(!redirected.starts_with(b"\x1b"));
        assert!(redirected.ends_with(b"Denied: 0\n"));
    }

    #[test]
    fn consume_request_is_strict_requester_bound_and_one_shot() {
        let mut b = broker();
        let p = b.propose(&proposal(), 1000);
        let v = view(&mut b, &p);
        assert_eq!(
            b.authority(&decision(&p, &v, "APPROVE_CHALLENGE"), 9001)["status"],
            "APPROVED"
        );
        let request = consume(&p);
        let mut injected = request.clone();
        injected["path"] = json!("/attacker");
        assert_eq!(b.consume_request(&injected, 1000)["code"], "UNKNOWN_FIELD");
        assert_eq!(
            b.consume_request(&request, 9001)["code"],
            "UNAUTHORIZED_REQUESTER"
        );
        assert_eq!(
            b.consume_request(&request, 1001)["code"],
            "UNAUTHORIZED_REQUESTER"
        );
        assert_eq!(b.consume_request(&request, 1000)["state"], "CONSUMED");
        assert_eq!(
            b.consume_request(&request, 1000)["code"],
            "ALREADY_CONSUMED"
        );
        let mut wrong_instance = request.clone();
        wrong_instance["broker_instance_id"] = json!("0".repeat(48));
        assert_eq!(
            b.consume_request(&wrong_instance, 1000)["code"],
            "BROKER_INSTANCE_MISMATCH"
        );
        let mut wrong_digest = request.clone();
        wrong_digest["request_digest"] = json!("0".repeat(64));
        assert_eq!(
            b.consume_request(&wrong_digest, 1000)["code"],
            "CHALLENGE_MISMATCH"
        );
    }
    #[test]
    fn unsupported_operation_types_never_enter_approval_state() {
        let mut b = broker();
        for ty in ["service_restart", "package_install", "unknown"] {
            let mut p = proposal();
            p["operations"][0]["type"] = json!(ty);
            assert_eq!(b.propose(&p, 1000)["code"], "UNSUPPORTED_OPERATION");
        }
        assert_eq!(
            b.propose(&exec_proposal(json!(["printf", "A"])), 1000)["status"],
            "PENDING_APPROVAL"
        );
    }
    #[test]
    fn duplicate_json_keys_are_rejected() {
        assert!(serde_json::from_str::<Unique>(
            r#"{"type":"PROPOSE_REQUEST","type":"APPROVE_CHALLENGE"}"#
        )
        .is_err());
    }
    #[test]
    fn renderer_escapes_controls() {
        let out = safe("/tmp/\u{1b}[31m\r\n\t\u{202e}\u{200b}\u{0430}");
        assert!(
            !out.contains('\u{1b}')
                && !out.contains('\r')
                && !out.contains('\n')
                && !out.contains('\t')
        );
        assert!(
            out.contains("\\u{202e}") && out.contains("\\u{200b}") && out.contains("\\u{0430}")
        );
    }
}
