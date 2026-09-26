//! Protocol-v5 broker-owned proposal and approval lifecycle. No execution exists here.
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
    os::{fd::AsRawFd, unix::net::UnixStream},
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
    Expired,
    Consumed,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PolicyDecision {
    Deny,
    RequireHumanApproval,
}
fn broker_policy(op: &str) -> PolicyDecision {
    if matches!(
        op,
        "file_patch" | "file_create" | "file_delete" | "file_move"
    ) {
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
}
struct Broker {
    instance: String,
    request_uid: u32,
    approver_uid: u32,
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
            if c.is_control() || !c.is_ascii() {
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
    if t == "file_patch" {
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
    fn new(request_uid: u32, approver_uid: u32) -> io::Result<Self> {
        Ok(Self {
            instance: random_id()?,
            request_uid,
            approver_uid,
            challenge_counter: 0,
            view_counter: 0,
            pending: HashMap::new(),
            views: HashMap::new(),
        })
    }
    fn expire(&mut self) {
        for r in self.pending.values_mut() {
            if matches!(r.state, State::Pending | State::Approved) && Instant::now() >= r.deadline {
                let _ = transition(&mut r.state, State::Expired);
                eprintln!("event=EXPIRED broker_instance_id={} challenge_id={} request_digest={} requester_uid={} target_uid={} target_gid={}",r.instance,r.challenge,r.digest,r.requester,r.target_uid,r.target_gid);
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
                eprintln!("event=VIEW_EXPIRED broker_instance_id={} challenge_id={} request_digest={} view_id_hash={} approver_uid={}",v.instance,v.challenge,v.digest,token_ref(id),v.approver_uid);
            }
        }
    }
    fn propose(&mut self, v: &Value, peer: u32) -> Value {
        self.expire();
        if peer == self.approver_uid {
            return response_error(
                "ROLE_SEPARATION_REQUIRED",
                "approver UID cannot submit requests",
            );
        }
        if peer != self.request_uid {
            return response_error(
                "UNAUTHORIZED_REQUESTER",
                "peer UID is not configured requester",
            );
        }
        let Some(o) = v.as_object() else {
            return response_error("INVALID_PROTOCOL", "message must be object");
        };
        if !only_keys(o, &["type", "protocol", "target", "operations"])
            || o.get("type").and_then(Value::as_str) != Some("PROPOSE_REQUEST")
            || o.get("protocol").and_then(Value::as_i64) != Some(VERSION)
        {
            return response_error("INVALID_PROTOCOL", "invalid proposal schema");
        }
        self.pending.retain(|_, r| {
            matches!(r.state, State::Pending | State::Approved) || Instant::now() < r.deadline
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
        if ops.len() != 1 {
            return response_error(
                "INVALID_OPERATION_COUNT",
                "exactly one operation is required",
            );
        }
        let op = &ops[0];
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
        let ttl = Duration::from_secs(MAX_TTL);
        let expires = now() + MAX_TTL as i64;
        let material = json!({"broker_instance_id":self.instance,"challenge_id":challenge,"expires_at":expires,"operations":ops,"protocol":VERSION,"requester_uid":peer,"target_gid":gid,"target_uid":uid});
        let mut h = Sha256::new();
        h.update(canonical(&material).as_bytes());
        let digest = hex::encode(h.finalize());
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
        };
        let mut req = req;
        if transition(&mut req.state, State::Pending).is_err() {
            return response_error("INVALID_STATE_TRANSITION", "proposal transition failed");
        }
        let path = ops[0]
            .get("path")
            .or_else(|| ops[0].get("source"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut ph = Sha256::new();
        ph.update(path.as_bytes());
        let path_id = hex::encode(ph.finalize());
        eprintln!("event=PROPOSED broker_instance_id={} challenge_id={} request_digest={} requester_uid={} target_uid={} target_gid={} operation={} path_id={} proposal_time={}",self.instance,challenge,digest,peer,uid,gid,ty,path_id,now());
        self.pending.insert(challenge.clone(), req);
        json!({"ok":true,"protocol":VERSION,"type":"PROPOSE_RESPONSE","broker_instance_id":self.instance,"challenge_id":challenge,"request_digest":digest,"status":"PENDING_APPROVAL","expires_at":expires})
    }
    fn render(&self, r: &Request, _view_id: &str, view_expires: i64) -> String {
        let mut out=format!("MAYI REQUEST\nBroker: {}\nChallenge: {}\nDigest: {}\nView expires: {}\nRequester UID: {}\nTarget UID/GID: {}/{}\nRequest expires: {}\n",r.instance,r.challenge,r.digest,view_expires,r.requester,r.target_uid,r.target_gid,r.expires);
        for op in &r.ops {
            let ty = op["type"].as_str().unwrap_or("unknown");
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
    fn authority(&mut self, v: &Value, peer: u32) -> Value {
        self.expire();
        if peer != self.approver_uid {
            return response_error(
                "UNAUTHORIZED_APPROVER",
                "peer UID is not configured approver",
            );
        }
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
                let items:Vec<_>=self.pending.values().filter(|r|r.state==State::Pending).map(|r|json!({"challenge_id":r.challenge,"request_digest":r.digest,"requester_uid":r.requester,"expires_at":r.expires})).collect();
                json!({"ok":true,"protocol":VERSION,"broker_instance_id":self.instance,"pending":items})
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
                        eprintln!("event=VIEW_REPLACED broker_instance_id={} challenge_id={} request_digest={} view_id_hash={} approver_uid={}",v.instance,v.challenge,v.digest,token_ref(&old),v.approver_uid)
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
                eprintln!("event=VIEW_CREATED broker_instance_id={} challenge_id={} request_digest={} view_id_hash={} approver_uid={} expires_at={}",view.instance,view.challenge,view.digest,token_ref(&view_id),peer,view.expires);
                self.views.insert(view_id.clone(), view);
                json!({"ok":true,"protocol":VERSION,"type":"CHALLENGE_VIEW","status":"DISPLAYED","broker_instance_id":self.instance,"challenge_id":id,"request_digest":snapshot.digest,"view_id":view_id,"view_expires_at":view_expires,"state":"PENDING_APPROVAL","rendered":rendered})
            }
            "APPROVE_CHALLENGE" | "DENY_CHALLENGE" | "EXPLAIN_CHALLENGE" => {
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
                    _ => None,
                };
                if let Some(next) = request_state {
                    let req = self.pending.get_mut(id).unwrap();
                    if transition(&mut req.state, next).is_err() {
                        return response_error(
                            "INVALID_STATE_TRANSITION",
                            "request transition rejected",
                        );
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
                eprintln!("event={} broker_instance_id={} challenge_id={} request_digest={} view_id_hash={} requester_uid={} target_uid={} target_gid={} approver_uid={}",event,req.instance,req.challenge,req.digest,token_ref(view_id),req.requester,req.target_uid,req.target_gid,peer);
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
        self.expire();
        if peer == self.approver_uid {
            return response_error(
                "ROLE_SEPARATION_REQUIRED",
                "approver UID cannot consume requests",
            );
        }
        if peer != self.request_uid {
            return response_error(
                "UNAUTHORIZED_REQUESTER",
                "peer UID is not configured requester",
            );
        }
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
            return response_error("BROKER_INSTANCE_MISMATCH", "broker instance mismatch");
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
        match r.state {
            State::Approved => {
                if transition(&mut r.state, State::Consumed).is_err() {
                    return response_error(
                        "INVALID_STATE_TRANSITION",
                        "consume transition rejected",
                    );
                }
                eprintln!(
                    "event=CONSUMED broker_instance_id={} challenge_id={} request_digest={} requester_uid={} target_uid={} target_gid={}",
                    r.instance, r.challenge, r.digest, r.requester, r.target_uid, r.target_gid
                );
                json!({"ok":true,"protocol":VERSION,"status":"CONSUMED","state":"CONSUMED","execution":"EXECUTION_DISABLED","broker_instance_id":r.instance,"challenge_id":r.challenge,"request_digest":r.digest})
            }
            State::Consumed => response_error("ALREADY_CONSUMED", "approval already consumed"),
            State::Expired => response_error("REQUEST_EXPIRED", "challenge expired"),
            _ => response_error("INVALID_STATE_TRANSITION", "request not approved"),
        }
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
fn console_call(path: &Path, broker_uid: u32, msg: &Value) -> io::Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut s = UnixStream::connect(path)?;
    if peer_uid(&s).ok() != Some(broker_uid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected broker peer UID",
        ));
    }
    write_frame_deadline(&mut s, msg, deadline)?;
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
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
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
    const MAX_INPUT: usize = 64;
    const QUIET_MS: u64 = 100;
    let fd = io::stdin().as_raw_fd();
    let _terminal = TerminalMode::raw(fd)?;
    let input_deadline = Instant::now() + Duration::from_secs(120);
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
        let wait_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        if !poll_input(fd, wait_ms)? {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "terminal input timed out",
            ));
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
        b"approve" => Some("APPROVE_CHALLENGE"),
        b"deny" => Some("DENY_CHALLENGE"),
        b"explain" => Some("EXPLAIN_CHALLENGE"),
        _ => None,
    }
}
pub fn approval_console(path: PathBuf, broker_uid: u32) -> io::Result<()> {
    if unsafe { libc::geteuid() } == 0
        || unsafe { libc::isatty(libc::STDIN_FILENO) } != 1
        || unsafe { libc::isatty(libc::STDOUT_FILENO) } != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approval console requires an unprivileged interactive terminal",
        ));
    }
    let list = console_call(
        &path,
        broker_uid,
        &json!({"type":"LIST_PENDING","protocol":VERSION}),
    )?;
    if list["ok"] != true || !valid_hex(list.get("broker_instance_id"), 48) {
        return Err(io::Error::other(
            "broker rejected or miscorrelated pending-list request",
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
    let view = console_call(
        &path,
        broker_uid,
        &json!({"type":"GET_CHALLENGE","protocol":VERSION,"broker_instance_id":instance,"challenge_id":challenge}),
    )?;
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
    print!("Decision [approve/deny/explain; input is not echoed]: ");
    io::stdout().flush()?;
    let frame = read_tty_frame()?;
    let decision = parse_decision(&frame)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid decision"))?;
    let response = console_call(
        &path,
        broker_uid,
        &json!({"type":decision,"protocol":VERSION,"broker_instance_id":instance,"challenge_id":challenge,"request_digest":digest,"view_id":view["view_id"]}),
    )?;
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
        "{} (filesystem execution remains disabled)",
        terminal_safe(response["status"].as_str().unwrap_or("REJECTED"))
    );
    Ok(())
}
fn handle(mut s: UnixStream, broker: &Arc<Mutex<Broker>>, approval: bool) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    let peer = peer_uid(&s).unwrap_or(u32::MAX);
    let v = match read_frame_deadline(&mut s, deadline).and_then(|b| {
        serde_json::from_slice::<Unique>(&b)
            .map(|u| u.0)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid JSON"))
    }) {
        Ok(v) => v,
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
    let mut state = broker
        .lock()
        .map_err(|_| io::Error::other("broker state poisoned"))?;
    let mut r = if approval {
        state.authority(&v, peer)
    } else if v.get("type").and_then(Value::as_str) == Some("CONSUME_APPROVED") {
        state.consume_request(&v, peer)
    } else {
        state.propose(&v, peer)
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
    drop(state);
    let out = r.to_string();
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "transaction deadline exceeded",
        ));
    }
    s.set_write_timeout(Some(left))?;
    s.write_all(&(out.len() as u32).to_be_bytes())?;
    s.write_all(out.as_bytes())
}
fn dispatch(
    stream: UnixStream,
    broker: Arc<Mutex<Broker>>,
    approval: bool,
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
            if let Err(e) = handle(stream, &broker, approval) {
                eprintln!(
                    "event=CONNECTION_ERROR role={} error={}",
                    role,
                    safe(&e.to_string())
                )
            }
            worker_active.fetch_sub(1, Ordering::Release);
        })
    {
        active.fetch_sub(1, Ordering::Release);
        eprintln!(
            "event=CONNECTION_REJECTED role={} reason=worker_spawn_failed error={}",
            role,
            safe(&e.to_string())
        );
    }
}

pub fn serve(
    request_path: PathBuf,
    approval_path: PathBuf,
    request_uid: u32,
    approver_uid: u32,
    request_gid: u32,
    approval_gid: u32,
    development_same_uid: bool,
) -> io::Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REAL_ROOT_DISABLED",
        ));
    }
    let broker_uid = unsafe { libc::geteuid() };
    if approver_uid == broker_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approver UID must differ from request broker UID",
        ));
    }
    if request_uid == approver_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "requester and approver UIDs must differ",
        ));
    }
    if !development_same_uid && request_gid == approval_gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "production request and approval socket groups must differ",
        ));
    }
    if request_uid == broker_uid && !development_same_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "requester and broker UIDs must differ outside explicit development mode",
        ));
    }
    if development_same_uid && request_uid != broker_uid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "development same-UID mode requires requester UID equal broker UID",
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
    let broker = Arc::new(Mutex::new(Broker::new(request_uid, approver_uid)?));
    let request_active = Arc::new(AtomicUsize::new(0));
    let approval_active = Arc::new(AtomicUsize::new(0));
    let req = super::listener_for(&request_path, request_gid)?;
    let auth = super::listener_for(&approval_path, approval_gid)?;
    req.set_nonblocking(true)?;
    auth.set_nonblocking(true)?;
    loop {
        let mut activity = false;
        match req.accept() {
            Ok((s, _)) => {
                activity = true;
                dispatch(s, broker.clone(), false, request_active.clone())
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        match auth.accept() {
            Ok((s, _)) => {
                activity = true;
                dispatch(s, broker.clone(), true, approval_active.clone())
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        if !activity {
            std::thread::sleep(Duration::from_millis(5))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn broker() -> Broker {
        Broker::new(1000, 9001).unwrap()
    }
    fn proposal() -> Value {
        json!({"type":"PROPOSE_REQUEST","protocol":5,"target":{"uid":1000,"gid":1000},"operations":[{"type":"file_create","path":"/etc/x","content":"x","expected_result_sha256":"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881","mode":"0644"}]})
    }
    fn view(b: &mut Broker, p: &Value) -> Value {
        b.authority(&json!({"type":"GET_CHALLENGE","protocol":5,"broker_instance_id":p["broker_instance_id"],"challenge_id":p["challenge_id"]}),9001)
    }
    fn decision(p: &Value, v: &Value, ty: &str) -> Value {
        json!({"type":ty,"protocol":5,"broker_instance_id":p["broker_instance_id"],"challenge_id":p["challenge_id"],"request_digest":p["request_digest"],"view_id":v["view_id"]})
    }
    fn consume(p: &Value) -> Value {
        json!({"type":"CONSUME_APPROVED","protocol":5,"broker_instance_id":p["broker_instance_id"],"challenge_id":p["challenge_id"],"request_digest":p["request_digest"]})
    }
    #[test]
    fn proposal_is_pending_and_client_cannot_approve() {
        let mut b = broker();
        let p = b.propose(&proposal(), 1000);
        assert_eq!(p["status"], "PENDING_APPROVAL");
        assert_eq!(
            b.authority(&json!({"type":"APPROVE_CHALLENGE","protocol":5}), 1000)["code"],
            "UNAUTHORIZED_APPROVER"
        );
        assert_eq!(
            b.propose(&proposal(), 9001)["code"],
            "ROLE_SEPARATION_REQUIRED"
        );
    }
    #[test]
    fn approval_is_one_shot_and_execution_disabled() {
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
        assert_eq!(consumed["execution"], "EXECUTION_DISABLED");
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
            State::Pending
        );
        assert_eq!(b.authority(&explain, 9001)["code"], "VIEW_ALREADY_USED");
        let v2 = view(&mut b, &p);
        assert_ne!(v1["view_id"], v2["view_id"]);
        assert_eq!(
            b.authority(&decision(&p, &v2, "APPROVE_CHALLENGE"), 9001)["status"],
            "APPROVED"
        );
        assert_eq!(
            b.consume_request(&consume(&p), 1000)["execution"],
            "EXECUTION_DISABLED"
        );
        let mut changed = proposal();
        changed["operations"][0]["path"] = Value::String("/etc/changed".into());
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
            "UNAUTHORIZED_APPROVER"
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
            b.pending[p["challenge_id"].as_str().unwrap()].ops[0]["path"],
            "/etc/x"
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
            "ROLE_SEPARATION_REQUIRED"
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
        for ty in ["exec", "service_restart", "package_install", "unknown"] {
            let mut p = proposal();
            p["operations"][0]["type"] = json!(ty);
            assert_eq!(b.propose(&p, 1000)["code"], "UNSUPPORTED_OPERATION");
        }
        assert!(b.pending.is_empty());
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
