use super::*;
use crate::audit::Field as F;

#[test]
fn queued_mapping_is_available_before_proposal_logging_and_views_reuse_it() {
    let mut broker = Broker::new().unwrap();
    let secret = "ARGUMENT_MUST_NEVER_BE_LOGGED";
    let queued=broker.propose(&json!({"type":"QUEUE_REQUEST","protocol":VERSION,"target":{"uid":1000,"gid":1000},"dependencies":[],"operations":[{"type":"exec","executable":"/usr/bin/true","argv":["true",secret]}]}),1000);
    assert_eq!(queued["status"], "PENDING_APPROVAL");
    let cid = queued["challenge_id"].as_str().unwrap();
    let expected = queued["request_id"].as_str().unwrap();
    let fields = request_audit_fields(&broker.pending[cid]);
    assert_eq!(
        fields.iter().find(|(f, _)| *f == F::RequestId).unwrap().1,
        expected
    );
    assert!(!format!("{fields:?}").contains(secret));
    assert!(!fields
        .iter()
        .any(|(f, _)| *f == F::ApproverUid || *f == F::ChildExitStatus));
    for uid in [9001, 9002] {
        let view=broker.authority(&json!({"type":"GET_CHALLENGE","protocol":VERSION,"broker_instance_id":queued["broker_instance_id"],"challenge_id":cid}),uid);
        assert_eq!(view["ok"], true);
        let active = broker.views.get(view["view_id"].as_str().unwrap()).unwrap();
        assert_eq!(active.challenge, cid);
        assert_eq!(
            request_audit_fields(&broker.pending[&active.challenge])
                .iter()
                .find(|(f, _)| *f == F::RequestId)
                .unwrap()
                .1,
            expected
        );
    }
    assert_eq!(broker.views.len(), 1); // replacement, not a one-view-ever cardinality assumption
    assert!(!Broker::new().unwrap().pending.contains_key(cid));
}
#[test]
fn failed_spawn_is_not_reported_as_observed_completion() {
    for queued in [false, true] {
        assert!(broker_execution_event(queued, "FAILED", false).ends_with("DISPATCH_FAILED"));
        assert!(broker_execution_event(queued, "FAILED", true).ends_with("FINISHED"));
        assert!(broker_execution_event(queued, "UNKNOWN", false).ends_with("OUTCOME_UNKNOWN"));
    }
}
#[test]
fn synchronous_requests_do_not_get_invented_queue_ids() {
    let mut broker = Broker::new().unwrap();
    let request=broker.propose(&json!({"type":"PROPOSE_REQUEST","protocol":VERSION,"target":{"uid":1000,"gid":1000},"operations":[{"type":"exec","executable":"/usr/bin/true","argv":["true"]}]}),1000);
    let cid = request["challenge_id"].as_str().unwrap();
    let fields = request_audit_fields(&broker.pending[cid]);
    assert!(fields.iter().any(|(f, _)| *f == F::ChallengeId));
    assert!(!fields.iter().any(|(f, _)| *f == F::RequestId));
}
