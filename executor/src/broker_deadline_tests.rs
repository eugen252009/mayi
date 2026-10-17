use super::*;

fn approved() -> (Broker, Value) {
    let mut b = Broker::new().unwrap();
    let p=b.propose(&json!({"type":"PROPOSE_REQUEST","protocol":5,"target":{"uid":1000,"gid":1000},"operations":[{"type":"exec","executable":"/usr/bin/true","argv":["true"]}]}),1000);
    b.pending
        .get_mut(p["challenge_id"].as_str().unwrap())
        .unwrap()
        .state = State::Approved;
    let c = json!({"type":"CONSUME_APPROVED","protocol":5,"broker_instance_id":p["broker_instance_id"],"challenge_id":p["challenge_id"],"request_digest":p["request_digest"]});
    (b, c)
}
#[test]
fn final_monotonic_boundary_is_exclusive_and_wall_time_cannot_revive() {
    let (mut b, c) = approved();
    let id = c["challenge_id"].as_str().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let r = b.pending.get_mut(id).unwrap();
    r.deadline = deadline;
    assert!(!expire_request_at(r, deadline - Duration::from_nanos(1)));
    assert_eq!(r.state, State::Approved);
    assert!(expire_request_at(r, deadline));
    assert_eq!(r.state, State::Expired);
    r.expires = i64::MAX;
    assert!(expire_request_at(r, deadline - Duration::from_secs(1)));
    assert!(expire_request_at(r, deadline + Duration::from_secs(1)));
    assert_eq!(b.consume_request(&c, 1000)["code"], "REQUEST_EXPIRED");
}
#[test]
fn expired_queue_claim_cannot_run_or_be_revived() {
    let (mut b, c) = approved();
    let r = b
        .pending
        .get_mut(c["challenge_id"].as_str().unwrap())
        .unwrap();
    r.queue_state = Some(QueueState::Ready);
    let deadline = r.deadline;
    assert!(expire_request_at(r, deadline));
    assert_eq!(r.queue_state, Some(QueueState::Expired));
    assert_eq!(r.mayi_result, Some(11));
    assert!(expire_request_at(r, deadline - Duration::from_secs(1)));
}
#[test]
fn dispatched_work_is_not_cancelled_by_expiry() {
    let (mut b, c) = approved();
    assert_eq!(b.consume_request(&c, 1000)["status"], "CONSUMED");
    let r = b
        .pending
        .get_mut(c["challenge_id"].as_str().unwrap())
        .unwrap();
    assert!(!expire_request_at(r, r.deadline + Duration::from_secs(1)));
    assert_eq!(r.state, State::Consumed);
    assert_eq!(b.consume_request(&c, 1000)["code"], "ALREADY_CONSUMED");
}
#[test]
fn delayed_concurrent_consumers_never_revive_expired_authority() {
    for _ in 0..12 {
        let (mut b, c) = approved();
        let id = c["challenge_id"].as_str().unwrap().to_owned();
        let deadline = Instant::now() + Duration::from_millis(20);
        b.pending.get_mut(&id).unwrap().deadline = deadline;
        let b = Arc::new(Mutex::new(b));
        let gate = Arc::new(std::sync::Barrier::new(9));
        let hold = b.lock().unwrap();
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let b = b.clone();
                let c = c.clone();
                let gate = gate.clone();
                std::thread::spawn(move || {
                    gate.wait();
                    b.lock().unwrap().consume_request(&c, 1000)
                })
            })
            .collect();
        gate.wait();
        while Instant::now() < deadline {
            std::thread::yield_now();
        }
        drop(hold);
        for worker in workers {
            assert_eq!(worker.join().unwrap()["code"], "REQUEST_EXPIRED");
        }
        assert_eq!(b.lock().unwrap().pending[&id].state, State::Expired);
    }
}
#[test]
fn approval_revalidates_request_and_view_after_authentication_delay() {
    for expire_view in [false, true] {
        let (mut b, c) = approved();
        let id = c["challenge_id"].as_str().unwrap();
        b.pending.get_mut(id).unwrap().state = State::Pending;
        let view=b.authority(&json!({"type":"GET_CHALLENGE","protocol":5,"broker_instance_id":c["broker_instance_id"],"challenge_id":id}),9001);
        let view_id = view["view_id"].as_str().unwrap();
        if expire_view {
            b.views.get_mut(view_id).unwrap().deadline = Instant::now();
        } else {
            b.pending.get_mut(id).unwrap().deadline = Instant::now();
        }
        let result=b.authority(&json!({"type":"APPROVE_CHALLENGE","protocol":5,"broker_instance_id":c["broker_instance_id"],"challenge_id":id,"request_digest":c["request_digest"],"view_id":view_id}),9001);
        assert_eq!(result["ok"], false);
        assert_ne!(b.pending[id].state, State::Approved);
        assert_eq!(b.consume_request(&c, 1000)["ok"], false);
    }
}
