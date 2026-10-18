//! Session control on the existing approval socket. Passwords stay inside PAM.
use super::*;

pub(super) fn control(
    stream: &UnixStream,
    broker: &Arc<Mutex<Broker>>,
    peer: PeerCredentials,
    role_gid: u32,
    request: &Value,
    terminal: Option<&OwnedFd>,
    authenticate: &impl Fn(u32, &Value, RawFd, bool) -> io::Result<bool>,
) -> Value {
    let attempt = || -> Result<Value, Value> {
        role_authorization(peer, role_gid, true)?;
        let ty = request["type"].as_str().unwrap_or("");
        let keys: &[&str] = if ty == "AUTHENTICATE_CONSOLE" {
            &["type", "protocol", "broker_instance_id"]
        } else {
            &["type", "protocol", "broker_instance_id", "console_session"]
        };
        if !request.as_object().is_some_and(|o| only_keys(o, keys))
            || request["protocol"] != VERSION
            || (ty != "AUTHENTICATE_CONSOLE" && !valid_hex(request.get("console_session"), 48))
        {
            return Err(response_error(
                "INVALID_PROTOCOL",
                "invalid console session request",
            ));
        }
        let terminal =
            terminal.ok_or_else(|| response_error("PAM_AUTH_REQUIRED", "terminal required"))?;
        let key = console_sessions::Key::from_peer(peer, terminal.as_raw_fd())
            .map_err(|_| response_error("PAM_AUTH_REQUIRED", "invalid terminal"))?;
        let mut state = broker
            .lock()
            .map_err(|_| response_error("INTERNAL_ERROR", "broker state poisoned"))?;
        if request["broker_instance_id"] != state.instance {
            return Err(response_error(
                "BROKER_INSTANCE_MISMATCH",
                "console belongs to another broker",
            ));
        }
        if ty != "AUTHENTICATE_CONSOLE" {
            let token = request["console_session"].as_str().unwrap();
            let now = Instant::now();
            let deadline = state.console_sessions.deadline(key, token, now);
            if ty == "END_CONSOLE_SESSION" && deadline.is_some() {
                state.console_sessions.revoke(key);
            }
            return Ok(
                json!({"ok":true,"protocol":VERSION,"active":ty != "END_CONSOLE_SESSION" && deadline.is_some(),
                "idle_remaining_seconds":deadline.map(|d| d.remaining(now).as_secs()).unwrap_or(0)}),
            );
        }
        // Reauthentication is fail-closed: a failed attempt cannot leave an old session usable.
        state.console_sessions.revoke(key);
        let instance = state.instance.clone();
        drop(state);
        let process = console_sessions::pin_process(key)
            .map_err(|_| response_error("PAM_AUTH_REQUIRED", "cannot pin console process"))?;
        let authentication_id = random_id()
            .map_err(|_| response_error("INTERNAL_ERROR", "random source unavailable"))?;
        let pam_request = json!({"type":"AUTHENTICATE_CONSOLE","broker_instance_id":instance,"authentication_id":authentication_id});
        if !authenticate(peer.uid, &pam_request, terminal.as_raw_fd(), false).unwrap_or(false) {
            return Err(response_error(
                "PAM_AUTHENTICATION_FAILED",
                "console authentication failed",
            ));
        }
        role_authorization(peer, role_gid, true)?;
        if !connection_usable(stream) {
            return Err(response_error(
                "AUTHENTICATION_CONNECTION_CLOSED",
                "console disconnected",
            ));
        }
        let mut state = broker
            .lock()
            .map_err(|_| response_error("INTERNAL_ERROR", "broker state poisoned"))?;
        let token = state
            .console_sessions
            .establish(
                key,
                process,
                Instant::now(),
                terminal
                    .try_clone()
                    .map_err(|_| response_error("INTERNAL_ERROR", "cannot retain terminal"))?,
            )
            .map_err(|_| response_error("CONSOLE_AUTH_REQUIRED", "session unavailable"))?;
        Ok(
            json!({"ok":true,"protocol":VERSION,"console_session":token,"idle_timeout_seconds":300,"active":true}),
        )
    };
    attempt().unwrap_or_else(|error| error)
}

pub(super) fn apply_decision(
    state: &mut Broker,
    request: &Value,
    peer: u32,
    key: Option<console_sessions::Key>,
    token: Option<&Value>,
) -> Value {
    let at = Instant::now();
    let grant = match token {
        None => None, // Legacy clients retain fresh per-decision PAM.
        Some(token) => {
            let Some((key, token)) = key.zip(token.as_str()) else {
                return response_error("CONSOLE_AUTH_REQUIRED", "invalid session binding");
            };
            let Some(deadline) = state.console_sessions.deadline(key, token, at) else {
                return response_error("CONSOLE_AUTH_REQUIRED", "console session expired");
            };
            Some((key, token, deadline))
        }
    };
    // Sample both monotonic clocks BEFORE the transition; response/logging delays
    // and suspend cannot grant extra idle time after a successful decision.
    let renewal = match console_sessions::Deadline::new(at) {
        Ok(deadline) => deadline,
        Err(_) if grant.is_some() => {
            return response_error("CONSOLE_AUTH_REQUIRED", "session clock unavailable")
        }
        Err(_) => return state.authority(request, peer),
    };
    let result = state.authority_with_session_deadline(request, peer, grant.map(|g| g.2));
    if result["ok"] == true
        && matches!(
            result["status"].as_str(),
            Some("APPROVED" | "DENIED" | "EXPLAINED")
        )
    {
        if let Some((key, token, _)) = grant {
            state
                .console_sessions
                .decision_succeeded(key, token, renewal);
        }
    }
    result
}

pub(super) struct Console {
    path: PathBuf,
    broker_uid: u32,
    pub instance: String,
    token: String,
}
impl Console {
    pub fn authenticate(path: &Path, broker_uid: u32) -> io::Result<Self> {
        let (instance, _) = console_snapshot(path, broker_uid)?;
        println!("Authenticate to unlock approvals (5-minute idle timeout).");
        let response = approval_decision_call(
            path,
            broker_uid,
            &json!({"type":"AUTHENTICATE_CONSOLE","protocol":VERSION,"broker_instance_id":instance}),
        )?;
        check_authority_response(&response)?;
        if response["broker_instance_id"] != instance
            || response["active"] != true
            || !valid_hex(response.get("console_session"), 48)
            || response["idle_timeout_seconds"] != 300
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid console authentication response",
            ));
        }
        Ok(Self {
            path: path.to_owned(),
            broker_uid,
            instance,
            token: response["console_session"].as_str().unwrap().to_owned(),
        })
    }
    fn message(&self, ty: &str) -> Value {
        json!({"type":ty,"protocol":VERSION,"broker_instance_id":self.instance,"console_session":self.token})
    }
    pub fn check(&self) -> io::Result<()> {
        let response = approval_decision_call(
            &self.path,
            self.broker_uid,
            &self.message("GET_CONSOLE_SESSION"),
        )?;
        check_authority_response(&response)?;
        if response["broker_instance_id"] != self.instance || response["active"] != true {
            return Err(io::Error::new(io::ErrorKind::TimedOut,
                "Console locked: authentication expired. Run mayi-approve to authenticate again; pending requests were not approved."));
        }
        Ok(())
    }
    pub fn bind(&self, message: &mut Value) {
        message["console_session"] = Value::String(self.token.clone());
    }
}
impl Drop for Console {
    fn drop(&mut self) {
        // Best effort on normal exit; pidfd death and monotonic expiry remain authoritative.
        let _ = approval_decision_call(
            &self.path,
            self.broker_uid,
            &self.message("END_CONSOLE_SESSION"),
        );
    }
}
