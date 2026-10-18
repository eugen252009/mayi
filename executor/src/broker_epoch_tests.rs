use super::*;
#[test]
fn authentic_old_v2_ids_are_distinct_from_forged_unknown_and_legacy() {
    let mut a = Broker::new().unwrap();
    let mut p = proposal();
    p["type"] = json!("QUEUE_REQUEST");
    p["dependencies"] = json!([]);
    let old = a.propose(&p, 1000);
    let id = old["request_id"].as_str().unwrap();
    assert!(id.starts_with("rq_v2_"));
    assert_eq!(
        crate::request_ids::authentic_epoch(&a.request_id_key, id),
        Some(a.instance.as_str())
    );
    let mut ids = HashSet::new();
    for _ in 0..1024 {
        assert!(ids.insert(
            crate::request_ids::issue(&a.request_id_key, &a.instance, &"d".repeat(64)).unwrap()
        ));
    }
    for _ in 0..5 {
        let mut b = Broker::new().unwrap();
        b.request_id_key = a.request_id_key;
        let request = json!({"type":"GET_QUEUE_STATUS","protocol":5,"request_id":id});
        let result = b.queue_status_request(&request, 1000);
        assert_eq!(result["code"], "BROKER_EPOCH_CHANGED");
        assert_eq!(
            result["error"],
            json!({"code":"BROKER_EPOCH_CHANGED","request_id":id,"retryable":false,"requires_new_request":true,"requires_new_approval":true})
        );
        assert_eq!(result["execution_outcome"], "UNKNOWN");
        assert!(b.pending.is_empty());
        let mut dependency = p.clone();
        dependency["dependencies"] = json!([id]);
        assert_eq!(b.propose(&dependency, 1000)["code"], "BROKER_EPOCH_CHANGED");
        assert!(b.pending.is_empty());
        let mut forged = id.as_bytes().to_vec();
        forged[6] = if forged[6] == b'a' { b'b' } else { b'a' };
        let forged = String::from_utf8(forged).unwrap();
        let request = json!({"type":"GET_QUEUE_STATUS","protocol":5,"request_id":forged});
        assert_eq!(
            b.queue_status_request(&request, 1000)["code"],
            "REQUEST_NOT_FOUND"
        );
        for unknown in [
            format!("rq_{}", "a".repeat(32)),
            crate::request_ids::issue(&b.request_id_key, &b.instance, &"e".repeat(64)).unwrap(),
        ] {
            let r = b.queue_status_request(
                &json!({"type":"GET_QUEUE_STATUS","protocol":5,"request_id":unknown}),
                1000,
            );
            assert_eq!(r["code"], "REQUEST_NOT_FOUND");
        }
    }
    let mut same = Broker::new().unwrap();
    same.request_id_key = a.request_id_key;
    same.instance = a.instance.clone();
    assert!(same.request_id_error(id).is_none());
    let request = json!({"type":"GET_QUEUE_STATUS","protocol":5,"request_id":id});
    let cid = old["challenge_id"].as_str().unwrap();
    for (state, qstate, code) in [
        (State::Denied, QueueState::Denied, "AUTHORITY_DENIED"),
        (State::Consumed, QueueState::Running, "REQUEST_CONSUMED"),
        (
            State::Consumed,
            QueueState::ExecutionUnknown,
            "OUTCOME_UNKNOWN",
        ),
        (State::Expired, QueueState::Expired, "REQUEST_EXPIRED"),
    ] {
        let r = a.pending.get_mut(cid).unwrap();
        r.state = state;
        r.queue_state = Some(qstate);
        assert_eq!(
            a.queue_status_request(&request, 1000)["authorization_error"],
            code
        );
    }
    assert_eq!(
        canonical(&json!({"b":[1,2],"a":{"x":"a\\u0000b"}})),
        canonical(&json!({"a":{"x":"a\\u0000b"},"b":[1,2]}))
    );
    assert_ne!(
        canonical(&json!(["a", "bc"])),
        canonical(&json!(["ab", "c"]))
    );
}
fn proposal() -> Value {
    json!({"type":"PROPOSE_REQUEST","protocol":5,"target":{"uid":1000,"gid":1000},"operations":[{"type":"exec","executable":"/usr/bin/true","argv":["true"]}]})
}
fn consume(p: &Value) -> Value {
    json!({"type":"CONSUME_APPROVED","protocol":5,"broker_instance_id":p["broker_instance_id"],"challenge_id":p["challenge_id"],"request_digest":p["request_digest"]})
}
#[test]
fn epoch_is_existing_192_bit_random_identity_and_old_authority_is_not_restored() {
    let mut seen = HashSet::new();
    for _ in 0..256 {
        let b = Broker::new().unwrap();
        assert_eq!(b.instance.len(), 48);
        assert!(valid_hex(Some(&json!(b.instance)), 48));
        assert!(seen.insert(b.instance));
    }
    let mut old = Broker::new().unwrap();
    let p = old.propose(&proposal(), 1000);
    let mut new = Broker::new().unwrap();
    let result = new.consume_request(&consume(&p), 1000);
    assert_eq!(result["code"], "BROKER_INSTANCE_MISMATCH");
    assert_eq!(result["authorization_state"], "INVALIDATED");
    assert_eq!(result["execution_outcome"], "UNKNOWN");
    assert_eq!(result["invalidation_reason"], "BROKER_RESTARTED");
    assert!(new.pending.is_empty());
}
#[test]
fn shutdown_fence_only_invalidates_before_irreversible_claim() {
    let mut b = Broker::new().unwrap();
    for (state, phase) in [
        (State::Pending, ExecutionPhase::Idle),
        (State::Approved, ExecutionPhase::Idle),
        (State::Consumed, ExecutionPhase::Idle),
        (State::Approved, ExecutionPhase::Dispatching),
        (State::Approved, ExecutionPhase::Started),
        (State::Consumed, ExecutionPhase::Finished),
        (State::Denied, ExecutionPhase::Idle),
        (State::Expired, ExecutionPhase::Idle),
    ] {
        let p = b.propose(&proposal(), 1000);
        let r = b
            .pending
            .get_mut(p["challenge_id"].as_str().unwrap())
            .unwrap();
        r.state = state;
        r.execution_phase = phase;
    }
    let records = b.begin_stopping();
    assert!(b.stopping);
    assert_eq!(
        records
            .iter()
            .filter(|(event, _)| *event == "REQUEST_INVALIDATED")
            .count(),
        2
    );
    for (_, fields) in records
        .iter()
        .filter(|(event, _)| *event == "REQUEST_INVALIDATED")
    {
        assert!(fields.contains(&(crate::audit::Field::State, "INVALIDATED".into())));
        assert!(fields.contains(&(crate::audit::Field::Reason, "BROKER_STOPPING".into())));
    }
    assert!(b.begin_stopping().is_empty());
    assert_eq!(b.propose(&proposal(), 1000)["code"], "BROKER_STOPPING");
    assert_eq!(b.queue_snapshot()["code"], "BROKER_STOPPING");
    assert_eq!(
        b.authority(&json!({"type":"LIST_PENDING","protocol":5}), 1000)["code"],
        "BROKER_STOPPING"
    );
}
#[test]
fn consumption_racing_shutdown_cannot_be_both_claimed_and_safe_invalidated() {
    for _ in 0..60 {
        let mut b = Broker::new().unwrap();
        let p = b.propose(&proposal(), 1000);
        b.pending
            .get_mut(p["challenge_id"].as_str().unwrap())
            .unwrap()
            .state = State::Approved;
        let b = Arc::new(Mutex::new(b));
        let go = Arc::new(std::sync::Barrier::new(3));
        let worker = b.clone();
        let ready = go.clone();
        let c = consume(&p);
        let t = std::thread::spawn(move || {
            ready.wait();
            worker.lock().unwrap().consume_request(&c, 1000)
        });
        let stopper = b.clone();
        let ready = go.clone();
        let s = std::thread::spawn(move || {
            ready.wait();
            stopper.lock().unwrap().begin_stopping()
        });
        go.wait();
        let result = t.join().unwrap();
        let records = s.join().unwrap();
        let invalid = records
            .iter()
            .any(|(event, _)| *event == "REQUEST_INVALIDATED");
        assert_ne!(invalid, result["status"] == "CONSUMED");
        assert_eq!(
            b.lock().unwrap().consume_request(&consume(&p), 1000)["code"],
            "BROKER_STOPPING"
        );
    }
}
#[test]
fn queue_epoch_pin_is_optional_for_legacy_but_strict_when_present() {
    let mut b = Broker::new().unwrap();
    let mut p = proposal();
    p["type"] = json!("QUEUE_REQUEST");
    p["dependencies"] = json!([]);
    let q = b.propose(&p, 1000);
    let mut status = json!({"type":"GET_QUEUE_STATUS","protocol":5,"request_id":q["request_id"]});
    assert_eq!(b.queue_status_request(&status, 1000)["ok"], true);
    status["broker_instance_id"] = json!("e".repeat(48));
    assert_eq!(
        b.queue_status_request(&status, 1000)["invalidation_reason"],
        "BROKER_RESTARTED"
    );
    status["broker_instance_id"] = json!("bad");
    assert_eq!(
        b.queue_status_request(&status, 1000)["code"],
        "INVALID_PROTOCOL"
    );
    status["broker_instance_id"] = json!(b.instance);
    assert_eq!(
        b.queue_status_request(&status, 1001)["code"],
        "UNAUTHORIZED_REQUESTER"
    );
}
