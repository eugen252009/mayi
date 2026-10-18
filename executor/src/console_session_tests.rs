//! Real framed UDS + SCM_RIGHTS + PTY paths with a synthetic PAM result only.
//! No host PAM calls, passwords, privileged services or runtime auth bypass.
use super::*;
use std::sync::atomic::AtomicBool;

struct Harness {
    state: Arc<Mutex<Broker>>,
    tty: OwnedFd,
    _master: OwnedFd,
    full: Arc<AtomicUsize>,
    account: Arc<AtomicUsize>,
    accept: Arc<AtomicBool>,
}
impl Harness {
    fn new() -> Self {
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        Self {
            state: Arc::new(Mutex::new(Broker::new().unwrap())),
            tty: unsafe { OwnedFd::from_raw_fd(slave) },
            _master: unsafe { OwnedFd::from_raw_fd(master) },
            full: Arc::new(AtomicUsize::new(0)),
            account: Arc::new(AtomicUsize::new(0)),
            accept: Arc::new(AtomicBool::new(true)),
        }
    }
    fn rpc(&self, request: Value, fd: Option<RawFd>, approval: bool) -> Value {
        self.rpc_as_role(request, fd, approval, unsafe { libc::getgid() })
    }
    fn rpc_as_role(&self, request: Value, fd: Option<RawFd>, approval: bool, gid: u32) -> Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (state, full, account, accept) = (
            self.state.clone(),
            self.full.clone(),
            self.account.clone(),
            self.accept.clone(),
        );
        let worker = std::thread::spawn(move || {
            handle_with_auth(
                server,
                &state,
                approval,
                gid,
                gid,
                &|_, _, _, account_only| {
                    if account_only {
                        account.fetch_add(1, Ordering::SeqCst);
                    } else {
                        full.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(accept.load(Ordering::SeqCst))
                },
            )
            .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        if let Some(fd) = fd {
            send_frame_with_fd(&mut client, &request, fd, deadline).unwrap();
        } else {
            write_frame_deadline(&mut client, &request, deadline).unwrap();
        }
        let bytes = read_frame_deadline(&mut client, deadline).unwrap();
        worker.join().unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
    fn message(&self, ty: &str, token: Option<&str>) -> Value {
        let mut v = json!({"type":ty,"protocol":VERSION,"broker_instance_id":self.state.lock().unwrap().instance});
        if let Some(token) = token {
            v["console_session"] = json!(token);
        }
        v
    }
    fn login(&self) -> String {
        let r = self.rpc(
            self.message("AUTHENTICATE_CONSOLE", None),
            Some(self.tty.as_raw_fd()),
            true,
        );
        assert_eq!(r["ok"], true, "{r}");
        r["console_session"].as_str().unwrap().into()
    }
    fn active(&self, token: &str) -> bool {
        self.rpc(
            self.message("GET_CONSOLE_SESSION", Some(token)),
            Some(self.tty.as_raw_fd()),
            true,
        )["active"]
            == true
    }
    fn decision(&self, token: Option<&str>, ty: &str) -> Value {
        let mut state = self.state.lock().unwrap();
        let p = state.propose(&json!({"type":"PROPOSE_REQUEST","protocol":VERSION,"target":{"uid":unsafe { libc::getuid() },"gid":unsafe { libc::getgid() }},"operations":[{"type":"exec","executable":"/usr/bin/true","argv":["true"]}]}), unsafe { libc::getuid() });
        assert_eq!(p["ok"], true, "{p}");
        let instance = state.instance.clone();
        let v = state.authority(&json!({"type":"GET_CHALLENGE","protocol":VERSION,"broker_instance_id":instance,"challenge_id":p["challenge_id"]}), unsafe { libc::getuid() });
        assert_eq!(v["ok"], true, "{v}");
        let mut d = json!({"type":ty,"protocol":VERSION,"broker_instance_id":state.instance,"challenge_id":p["challenge_id"],"request_digest":p["request_digest"],"view_id":v["view_id"]});
        if let Some(token) = token {
            d["console_session"] = json!(token);
        }
        d
    }
    fn key(&self) -> console_sessions::Key {
        console_sessions::Key::from_peer(
            PeerCredentials {
                uid: unsafe { libc::getuid() },
                pid: std::process::id() as i32,
                gid: unsafe { libc::getgid() },
            },
            self.tty.as_raw_fd(),
        )
        .unwrap()
    }
}

#[test]
fn login_decisions_refresh_but_reads_do_not_and_legacy_still_authenticates() {
    let h = Harness::new();
    let token = h.login();
    let key = h.key();
    let initial = h
        .state
        .lock()
        .unwrap()
        .console_sessions
        .deadline(key, &token, Instant::now())
        .unwrap();
    assert!(h.active(&token));
    assert_eq!(
        h.state
            .lock()
            .unwrap()
            .console_sessions
            .deadline(key, &token, Instant::now()),
        Some(initial)
    );
    for ty in ["APPROVE_CHALLENGE", "DENY_CHALLENGE", "EXPLAIN_CHALLENGE"] {
        let request = h.decision(Some(&token), ty);
        let r = h.rpc(request, Some(h.tty.as_raw_fd()), true);
        assert_eq!(r["ok"], true, "{r}");
        assert!(
            h.state
                .lock()
                .unwrap()
                .console_sessions
                .deadline(key, &token, Instant::now())
                .unwrap()
                > initial
        );
    }
    assert_eq!(h.full.load(Ordering::SeqCst), 1);
    assert_eq!(h.account.load(Ordering::SeqCst), 3);
    let legacy = h.decision(None, "DENY_CHALLENGE");
    assert_eq!(h.rpc(legacy, Some(h.tty.as_raw_fd()), true)["ok"], true);
    assert_eq!(h.full.load(Ordering::SeqCst), 2);
    h.rpc(
        h.message("END_CONSOLE_SESSION", Some(&token)),
        Some(h.tty.as_raw_fd()),
        true,
    );
    assert!(!h.active(&token));
}

#[test]
fn expiry_forgery_missing_terminal_wrong_terminal_and_requester_socket_fail_closed() {
    let h = Harness::new();
    let token = h.login();
    let d = h.decision(Some(&token), "APPROVE_CHALLENGE");
    assert_eq!(
        h.rpc(d.clone(), None, true)["code"],
        "CONSOLE_AUTH_REQUIRED"
    );
    let token = h.login();
    let d = h.decision(Some(&token), "APPROVE_CHALLENGE");
    let other = Harness::new();
    assert_eq!(
        h.rpc(d, Some(other.tty.as_raw_fd()), true)["code"],
        "CONSOLE_AUTH_REQUIRED"
    );
    assert!(h.active(&token));
    let forged = h.decision(Some(&"f".repeat(48)), "APPROVE_CHALLENGE");
    assert_eq!(
        h.rpc(forged, Some(h.tty.as_raw_fd()), true)["code"],
        "CONSOLE_AUTH_REQUIRED"
    );
    let token = h.login();
    let d = h.decision(Some(&token), "APPROVE_CHALLENGE");
    assert_ne!(h.rpc(d.clone(), Some(h.tty.as_raw_fd()), false)["ok"], true);
    h.state
        .lock()
        .unwrap()
        .console_sessions
        .prune(Instant::now() + console_sessions::IDLE);
    assert_eq!(
        h.rpc(d, Some(h.tty.as_raw_fd()), true)["code"],
        "CONSOLE_AUTH_REQUIRED"
    );
    assert!(!h.active(&token));
    assert_eq!(h.account.load(Ordering::SeqCst), 0);
}

#[test]
fn failed_reauthentication_account_denial_replay_and_restart_do_not_keep_authority() {
    let h = Harness::new();
    let token = h.login();
    h.accept.store(false, Ordering::SeqCst);
    let failed = h.rpc(
        h.message("AUTHENTICATE_CONSOLE", None),
        Some(h.tty.as_raw_fd()),
        true,
    );
    assert_eq!(failed["code"], "PAM_AUTHENTICATION_FAILED");
    assert!(!h.active(&token));
    h.accept.store(true, Ordering::SeqCst);
    let token = h.login();
    let d = h.decision(Some(&token), "DENY_CHALLENGE");
    h.accept.store(false, Ordering::SeqCst);
    assert_eq!(
        h.rpc(d, Some(h.tty.as_raw_fd()), true)["code"],
        "PAM_AUTHENTICATION_FAILED"
    );
    assert!(!h.active(&token));
    h.accept.store(true, Ordering::SeqCst);
    let token = h.login();
    let d = h.decision(Some(&token), "DENY_CHALLENGE");
    assert_eq!(h.rpc(d.clone(), Some(h.tty.as_raw_fd()), true)["ok"], true);
    assert_ne!(h.rpc(d, Some(h.tty.as_raw_fd()), true)["ok"], true);
    assert!(!h.active(&token));
    let token = h.login();
    let old = h.message("GET_CONSOLE_SESSION", Some(&token));
    *h.state.lock().unwrap() = Broker::new().unwrap();
    assert_eq!(
        h.rpc(old, Some(h.tty.as_raw_fd()), true)["code"],
        "BROKER_INSTANCE_MISMATCH"
    );
}

#[test]
fn login_rejects_extra_identity_fields_wrong_instance_and_non_tty() {
    let h = Harness::new();
    let mut request = h.message("AUTHENTICATE_CONSOLE", None);
    request["peer_uid"] = json!(0);
    assert_eq!(
        h.rpc(request, Some(h.tty.as_raw_fd()), true)["code"],
        "INVALID_PROTOCOL"
    );
    let mut request = h.message("AUTHENTICATE_CONSOLE", None);
    request["broker_instance_id"] = json!("f".repeat(48));
    assert_eq!(
        h.rpc(request, Some(h.tty.as_raw_fd()), true)["code"],
        "BROKER_INSTANCE_MISMATCH"
    );
    let null = fs::File::open("/dev/null").unwrap();
    assert_eq!(
        h.rpc(
            h.message("AUTHENTICATE_CONSOLE", None),
            Some(null.as_raw_fd()),
            true
        )["code"],
        "PAM_AUTH_REQUIRED"
    );
    assert_eq!(
        h.rpc(h.message("AUTHENTICATE_CONSOLE", None), None, true)["code"],
        "PAM_AUTH_REQUIRED"
    );
    assert_eq!(h.full.load(Ordering::SeqCst), 0);
}

#[test]
fn lost_nss_role_revokes_cached_authentication() {
    let h = Harness::new();
    let token = h.login();
    let denied_gid = u32::MAX - 1;
    assert_eq!(
        uid_in_group(unsafe { libc::getuid() }, denied_gid).unwrap(),
        Some(false)
    );
    let denied = h.rpc_as_role(
        h.message("GET_CONSOLE_SESSION", Some(&token)),
        Some(h.tty.as_raw_fd()),
        true,
        denied_gid,
    );
    assert_eq!(denied["code"], "UNAUTHORIZED_APPROVER");
    // Restoring the role does not restore the session.
    assert!(!h.active(&token));
    assert_eq!(h.full.load(Ordering::SeqCst), 1);
}

#[test]
fn terminal_disconnect_invalidates_retained_session() {
    let mut h = Harness::new();
    let token = h.login();
    let key = h.key();
    let master = std::mem::replace(&mut h._master, fs::File::open("/dev/null").unwrap().into());
    drop(master);
    assert!(h
        .state
        .lock()
        .unwrap()
        .console_sessions
        .deadline(key, &token, Instant::now())
        .is_none());
}

#[test]
fn inherited_token_does_not_authorize_a_child_process() {
    use std::os::unix::net::UnixListener;
    let h = Harness::new();
    let token = h.login();
    let path = std::env::temp_dir().join(format!("mayi-session-{}.sock", random_id().unwrap()));
    let listener = UnixListener::bind(&path).unwrap();
    let request = h.message("GET_CONSOLE_SESSION", Some(&token));
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let mut client = UnixStream::connect(&path).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        send_frame_with_fd(&mut client, &request, h.tty.as_raw_fd(), deadline).unwrap();
        let response: Value =
            serde_json::from_slice(&read_frame_deadline(&mut client, deadline).unwrap()).unwrap();
        unsafe {
            libc::_exit(if response["active"] == false { 0 } else { 1 });
        }
    }
    let (stream, _) = listener.accept().unwrap();
    assert_eq!(peer_credentials(&stream).unwrap().pid, pid);
    let gid = unsafe { libc::getgid() };
    handle_with_auth(stream, &h.state, true, gid, gid, &|_, _, _, _| {
        panic!("status must not authenticate")
    })
    .unwrap();
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0);
    assert!(h.active(&token));
    fs::remove_file(path).unwrap();
}

#[test]
fn controlling_tty_descriptor_is_resolved_in_receiving_process() {
    let h = Harness::new();
    let (mut parent, mut child) = UnixStream::pair().unwrap();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        drop(parent);
        assert!(unsafe { libc::setsid() } >= 0);
        assert_eq!(
            unsafe { libc::ioctl(h.tty.as_raw_fd(), libc::TIOCSCTTY, 0) },
            0
        );
        let tty = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        send_frame_with_fd(
            &mut child,
            &json!({"ready":true}),
            tty.as_raw_fd(),
            deadline,
        )
        .unwrap();
        read_frame_deadline(&mut child, deadline).unwrap();
        unsafe {
            libc::_exit(0);
        }
    }
    drop(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    let (_, fd) = read_frame_with_fd(&mut parent, deadline).unwrap();
    assert!(console_sessions::Key::from_peer(
        PeerCredentials {
            pid,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() }
        },
        fd.unwrap().as_raw_fd()
    )
    .is_ok());
    write_frame_deadline(&mut parent, &json!({"done":true}), deadline).unwrap();
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0);
}

#[test]
fn session_deadline_is_rechecked_at_request_transition() {
    let h = Harness::new();
    let mut d = h.decision(None, "APPROVE_CHALLENGE");
    let r = h.state.lock().unwrap().authority_with_session_deadline(
        &d,
        unsafe { libc::getuid() },
        Some(console_sessions::Deadline::new(Instant::now() - console_sessions::IDLE).unwrap()),
    );
    assert_eq!(r["code"], "CONSOLE_AUTH_REQUIRED");
    // No request or view consumption occurred when the session expired.
    d["type"] = json!("DENY_CHALLENGE");
    assert_eq!(
        h.state
            .lock()
            .unwrap()
            .authority(&d, unsafe { libc::getuid() })["status"],
        "DENIED"
    );
}
