use super::*;

thread_local! {
    static STALL_UNTIL: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}
pub(super) fn after_expiry_sweep() {
    if let Some(deadline) = STALL_UNTIL.with(|s| s.take()) {
        while Instant::now() < deadline {
            std::thread::yield_now();
        }
    }
}

#[test]
fn consumption_rechecks_deadline_after_expiry_sweep() {
    let mut b = Broker::new().unwrap();
    let p = b.propose(&exec(), 1000);
    let id = p["challenge_id"].as_str().unwrap();
    let deadline = Instant::now() + Duration::from_millis(20);
    let r = b.pending.get_mut(id).unwrap();
    r.state = State::Approved;
    r.deadline = deadline;
    STALL_UNTIL.with(|s| s.set(Some(deadline)));
    let c = json!({"type":"CONSUME_APPROVED","protocol":5,"broker_instance_id":p["broker_instance_id"],"challenge_id":p["challenge_id"],"request_digest":p["request_digest"]});
    assert_eq!(b.consume_request(&c, 1000)["code"], "REQUEST_EXPIRED");
    assert_eq!(b.pending[id].state, State::Expired);
    assert_eq!(b.consume_request(&c, 1000)["code"], "REQUEST_EXPIRED");
}

#[test]
fn queued_dependency_wait_rechecks_deadline_after_expiry_sweep() {
    let mut b = Broker::new().unwrap();
    let mut p = exec();
    p["type"] = json!("QUEUE_REQUEST");
    p["dependencies"] = json!([]);
    let parent = b.propose(&p, 1000);
    p["dependencies"] = json!([parent["request_id"]]);
    let child = b.propose(&p, 1000);
    let id = child["challenge_id"].as_str().unwrap().to_owned();
    let deadline = Instant::now() + Duration::from_millis(20);
    let r = b.pending.get_mut(&id).unwrap();
    r.state = State::Approved;
    r.queue_state = Some(QueueState::WaitingDependency);
    r.deadline = deadline;
    STALL_UNTIL.with(|s| s.set(Some(deadline)));
    let b = Arc::new(Mutex::new(b));
    run_queue_scheduler(&b);
    assert_eq!(
        b.lock().unwrap().pending[&id].queue_state,
        Some(QueueState::Expired)
    );
}

fn exec() -> Value {
    json!({"type":"PROPOSE_REQUEST","protocol":5,"target":{"uid":1000,"gid":1000},"operations":[{"type":"exec","executable":"/usr/bin/true","argv":["true"]}]})
}

#[test]
fn disconnected_operations_cannot_poison_pending_console_rows() {
    let digest = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881";
    let operations = [
        json!({"type":"file_create","path":"/var/tmp/mayi-adversarial-never-created","content":"x","expected_result_sha256":digest,"mode":"0644"}),
        json!({"type":"file_patch","path":"/etc/x","expected_base_sha256":digest,"expected_result_sha256":digest,"patch":[{"old":"x","new":"y"}]}),
        json!({"type":"file_delete","path":"/etc/x","expected_sha256":digest}),
        json!({"type":"file_move","source":"/etc/x","destination":"/etc/y","expected_source_sha256":digest}),
    ];
    for operation in operations {
        for ty in ["PROPOSE_REQUEST", "QUEUE_REQUEST"] {
            let mut b = Broker::new().unwrap();
            let good = b.propose(&exec(), 1000);
            assert_eq!(good["status"], "PENDING_APPROVAL");
            let mut bad = exec();
            bad["type"] = json!(ty);
            if ty == "QUEUE_REQUEST" {
                bad["dependencies"] = json!([]);
            }
            bad["operations"] = json!([operation]);
            for _ in 0..10 {
                let response = b.propose(&bad, 1001);
                assert_eq!(response["code"], "UNSUPPORTED_OPERATION", "{response}");
                assert_eq!(b.pending.len(), 1);
                assert!(b.views.is_empty());
            }
            assert_eq!(b.pending.values().next().unwrap().ops[0]["type"], "exec");
        }
    }
}

#[test]
fn malformed_exec_never_enters_approval_state() {
    for operation in [
        json!({"type":"exec","executable":"/usr/bin/true","argv":["true"],"shell":"bad"}),
        json!({"type":"exec","executable":"/usr/bin/true","argv":"true"}),
        json!({"type":"exec","executable":"/usr/bin/true","argv":["true",null]}),
        json!({"type":"exec","executable":"/usr/bin/true","argv":["x\u{0}y"]}),
        json!({"type":"unknown","path":"\u{1b}[2J"}),
    ] {
        let mut b = Broker::new().unwrap();
        let mut p = exec();
        p["operations"] = json!([operation]);
        assert_eq!(b.propose(&p, 1000)["ok"], false);
        assert!(b.pending.is_empty());
    }
}

#[test]
fn valid_exec_terminal_controls_are_rendered_as_inert_text() {
    let mut b = Broker::new().unwrap();
    let mut proposal = exec();
    proposal["operations"][0]["argv"] = json!([
        "true",
        "\u{1b}[2J\u{1b}]0;requester-title\u{7}\rspoofed\nline",
        "\u{202e}txt"
    ]);
    let accepted = b.propose(&proposal, 1000);
    assert_eq!(accepted["status"], "PENDING_APPROVAL");
    let id = accepted["challenge_id"].as_str().unwrap();
    let rendered = b.render(&b.pending[id], "unused", now() + 60);
    let console = approval_ui::render(
        &b.authority(&json!({"type":"LIST_PENDING","protocol":VERSION}), 9001)["pending"]
            .as_array()
            .unwrap()
            .clone(),
        &[0],
        true,
        0,
        100,
        100,
    )
    .0;
    for output in [rendered, console] {
        assert!(!output.contains('\u{1b}'));
        assert!(!output.contains('\u{7}'));
        assert!(!output.contains('\r'));
        assert!(output.contains("\\u001b"));
        assert!(output.contains("\\u0007"));
        assert!(output.contains("\\u{202e}"));
    }
}
