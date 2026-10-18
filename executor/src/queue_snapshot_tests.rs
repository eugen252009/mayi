use super::*;

fn proposal(queued: bool, owner: u32, deps: &[Value]) -> Value {
    let mut value = json!({"type":"PROPOSE_REQUEST","protocol":5,"target":{"uid":owner,"gid":owner},"operations":[{"type":"exec","executable":"/usr/bin/true","argv":["true"]}]});
    if queued {
        value["type"] = json!("QUEUE_REQUEST");
        value["dependencies"] = json!(deps);
    }
    value
}
fn sum(v: &Value) -> u64 {
    [
        "pending_approval",
        "waiting_dependency",
        "approved_ready",
        "awaiting_consumption",
        "dispatching",
        "running",
    ]
    .iter()
    .map(|k| v[k].as_u64().unwrap())
    .sum()
}
#[test]
fn snapshot_empty_and_immutable_expiry() {
    let mut b = Broker::new().unwrap();
    assert_eq!(b.queue_snapshot()["total_active"], 0);
    let p = b.propose(&proposal(false, 1000, &[]), 1000);
    let id = p["challenge_id"].as_str().unwrap();
    b.pending.get_mut(id).unwrap().deadline = Instant::now();
    let counters = (b.challenge_counter, b.view_counter, b.views.len());
    for _ in 0..100 {
        assert_eq!(b.queue_snapshot()["total_active"], 0);
    }
    assert_eq!(b.pending[id].state, State::Pending);
    assert_eq!(
        counters,
        (b.challenge_counter, b.view_counter, b.views.len())
    );
}
#[test]
fn snapshot_categories_are_exclusive_and_do_not_count_views_or_edges() {
    let mut b = Broker::new().unwrap();
    let parent = b.propose(&proposal(true, 1000, &[]), 1000);
    let child = b.propose(&proposal(true, 1000, &[parent["request_id"].clone()]), 1000);
    let shared = b.propose(
        &proposal(
            true,
            1000,
            &[parent["request_id"].clone(), child["request_id"].clone()],
        ),
        1000,
    );
    b.pending
        .get_mut(child["challenge_id"].as_str().unwrap())
        .unwrap()
        .state = State::Approved;
    b.pending
        .get_mut(shared["challenge_id"].as_str().unwrap())
        .unwrap()
        .state = State::Approved;
    let s = b.queue_snapshot();
    assert_eq!(s["pending_approval"], 1);
    assert_eq!(s["waiting_dependency"], 2);
    assert_eq!(sum(&s), 3);
    let r = b
        .pending
        .get_mut(parent["challenge_id"].as_str().unwrap())
        .unwrap();
    r.queue_state = Some(QueueState::Succeeded);
    r.state = State::Consumed;
    let s = b.queue_snapshot();
    assert_eq!(s["approved_ready"], 1);
    assert_eq!(s["waiting_dependency"], 1);
    assert_eq!(sum(&s), 2);
}
#[test]
fn snapshot_dispatch_is_not_running_and_terminal_is_not_active() {
    let mut b = Broker::new().unwrap();
    let p = b.propose(&proposal(true, 1000, &[]), 1000);
    let id = p["challenge_id"].as_str().unwrap();
    {
        let r = b.pending.get_mut(id).unwrap();
        r.queue_state = Some(QueueState::Running);
        r.execution_phase = ExecutionPhase::Dispatching;
        r.deadline = Instant::now();
    }
    assert_eq!(b.queue_snapshot()["running"], 0);
    assert_eq!(b.queue_snapshot()["dispatching"], 1);
    b.pending.get_mut(id).unwrap().execution_phase = ExecutionPhase::Started;
    assert_eq!(b.queue_snapshot()["running"], 1);
    assert_eq!(b.queue_snapshot()["dispatching"], 0);
    for terminal in [
        QueueState::Succeeded,
        QueueState::Failed,
        QueueState::Denied,
        QueueState::Expired,
        QueueState::ExplainRequested,
        QueueState::Blocked,
        QueueState::ExecutionUnknown,
    ] {
        b.pending.get_mut(id).unwrap().queue_state = Some(terminal);
        assert_eq!(b.queue_snapshot()["total_active"], 0);
    }
}
#[test]
fn snapshot_synchronous_approved_and_execution_are_observed_separately() {
    let mut b = Broker::new().unwrap();
    let p = b.propose(&proposal(false, 1000, &[]), 1000);
    let id = p["challenge_id"].as_str().unwrap();
    b.pending.get_mut(id).unwrap().state = State::Approved;
    assert_eq!(b.queue_snapshot()["awaiting_consumption"], 1);
    {
        let r = b.pending.get_mut(id).unwrap();
        r.state = State::Consumed;
        r.execution_phase = ExecutionPhase::Started;
    }
    assert_eq!(b.queue_snapshot()["running"], 1);
    b.pending.get_mut(id).unwrap().execution_phase = ExecutionPhase::Finished;
    assert_eq!(b.queue_snapshot()["total_active"], 0);
}
#[test]
fn synchronous_observations_survive_retention_without_restoring_authority() {
    let mut b = Broker::new().unwrap();
    let p = b.propose(&proposal(false, 1000, &[]), 1000);
    let id = p["challenge_id"].as_str().unwrap().to_owned();
    b.synchronous_executions
        .insert(id.clone(), ExecutionPhase::Started);
    b.pending.remove(&id); // same effect as existing consumed-request retention
    assert_eq!(b.queue_snapshot()["running"], 1);
    assert!(b.pending.is_empty() && b.views.is_empty());
    b.synchronous_executions.remove(&id);
    assert_eq!(b.queue_snapshot()["total_active"], 0);
}
#[test]
fn snapshot_large_retained_queue_is_bounded_and_consistent_under_changes() {
    let mut b = Broker::new().unwrap();
    for owner in 1000..1016 {
        for _ in 0..8 {
            assert_eq!(b.propose(&proposal(true, owner, &[]), owner)["ok"], true);
        }
    }
    assert_eq!(b.pending.len(), 128);
    assert_eq!(b.queue_snapshot()["pending_approval"], 128);
    let b = Arc::new(Mutex::new(b));
    let worker = b.clone();
    let t = std::thread::spawn(move || {
        for _ in 0..1000 {
            let mut b = worker.lock().unwrap();
            for r in b.pending.values_mut() {
                r.state = if r.state == State::Pending {
                    State::Approved
                } else {
                    State::Pending
                };
            }
        }
    });
    for _ in 0..1000 {
        let snapshot = b.lock().unwrap().queue_snapshot();
        assert_eq!(snapshot["total_active"].as_u64(), Some(sum(&snapshot)));
        assert_eq!(sum(&snapshot), 128);
    }
    t.join().unwrap();
}
fn ipc(value: Value, approval: bool, gid: u32) -> Value {
    let b = Arc::new(Mutex::new(Broker::new().unwrap()));
    let server = b.clone();
    let (mut client, stream) = UnixStream::pair().unwrap();
    let t = std::thread::spawn(move || {
        handle_with_auth(stream, &server, approval, gid, gid, &|_, _, _, _| {
            panic!("status must not authenticate")
        })
        .unwrap()
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    write_frame_deadline(&mut client, &value, deadline).unwrap();
    let body = read_frame_deadline(&mut client, deadline).unwrap();
    t.join().unwrap();
    assert!(b.lock().unwrap().views.is_empty());
    serde_json::from_slice(&body).unwrap()
}
#[test]
fn snapshot_ipc_requires_approver_transport_role_and_exact_message() {
    let gid = unsafe { libc::getgid() };
    assert_eq!(
        ipc(json!({"type":"QUEUE_STATUS","protocol":5}), true, gid)["total_active"],
        0
    );
    assert_eq!(
        ipc(json!({"type":"QUEUE_STATUS","protocol":5}), false, gid)["ok"],
        false
    );
    assert_eq!(
        ipc(
            json!({"type":"QUEUE_STATUS","protocol":5,"uid":0}),
            true,
            gid
        )["ok"],
        false
    );
    assert_eq!(
        ipc(json!({"type":"QUEUE_STATUS","protocol":4}), true, gid)["ok"],
        false
    );
    assert_eq!(
        ipc(json!({"type":"QUEUE_STATUS","protocol":5}), true, u32::MAX)["ok"],
        false
    );
}
#[test]
fn start_observation_is_correlated_and_final_frame_remains_required() {
    for (id, duplicate, expected) in [
        ("1".repeat(32), false, true),
        ("2".repeat(32), false, false),
        ("1".repeat(32), true, false),
    ] {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let t = std::thread::spawn(move || {
            let frame = json!({"type":"EXEC_STARTED","protocol":1,"request_id":id});
            let _ = write_frame_deadline(&mut server, &frame, deadline);
            let final_frame = if duplicate {
                frame
            } else {
                json!({"type":"EXEC_RESPONSE","protocol":1,"request_id":"1".repeat(32),"status":"EXECUTED"})
            };
            let _ = write_frame_deadline(&mut server, &final_frame, deadline);
        });
        let called = std::cell::Cell::new(false);
        let result =
            read_executor_response(&mut client, deadline, &"1".repeat(32), || called.set(true));
        assert_eq!(result.is_ok(), expected);
        if expected {
            assert!(called.get());
        }
        t.join().unwrap();
    }
}
