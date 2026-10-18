//! Existing broker identity is the epoch. No persisted authority or replay.
use super::*;

impl Broker {
    /// Only a valid MAC under the retained local provenance key proves an old
    /// rq_v2 epoch. Caller-supplied metadata and lookup misses do not.
    pub(super) fn request_id_error(&self, id: &str) -> Option<Value> {
        if !crate::request_ids::valid(id) {
            return Some(response_error("INVALID_REQUEST_ID", "invalid request ID"));
        }
        crate::request_ids::parts(id)?;
        match crate::request_ids::authentic_epoch(&self.request_id_key, id) {
            None => Some(response_error("REQUEST_NOT_FOUND", "request is unknown")),
            Some(epoch) if epoch != self.instance => {
                let mut v=response_error("BROKER_EPOCH_CHANGED","authenticated request belongs to a previous broker epoch; reconcile execution before creating any fresh request and approval");
                v["request_id"] = json!(id);
                v["epoch_id"] = json!(epoch);
                v["broker_instance_id"] = json!(self.instance);
                v["authorization_state"] = json!("INVALIDATED");
                v["execution_outcome"] = json!("UNKNOWN");
                v["recovery_classification"] = json!("RECONCILIATION_REQUIRED");
                v["error"] = json!({"code":"BROKER_EPOCH_CHANGED","request_id":id,"retryable":false,"requires_new_request":true,"requires_new_approval":true});
                Some(v)
            }
            Some(_) => None,
        }
    }
    pub(super) fn instance_mismatch(&self) -> Value {
        let mut value = response_error(
            "BROKER_INSTANCE_MISMATCH",
            "authorization belongs to a different broker instance",
        );
        value["broker_instance_id"] = json!(self.instance);
        value["invalidation_reason"] = json!("BROKER_RESTARTED");
        value["authorization_state"] = json!("INVALIDATED");
        value["execution_outcome"] = json!("UNKNOWN");
        value["recovery_classification"] = json!("RECONCILIATION_REQUIRED");
        value
    }
    pub(super) fn stopping_response(&self) -> Value {
        let mut value = response_error(
            "BROKER_STOPPING",
            "broker shutdown has fenced authorization; reconnect and reconcile",
        );
        value["broker_instance_id"] = json!(self.instance);
        value
    }
    /// Fence under the SAME mutex as approval/consumption/queue claims. Collect
    /// metadata here; never emit IO or guess outstanding execution under lock.
    pub(super) fn begin_stopping(
        &mut self,
    ) -> Vec<(&'static str, Vec<(crate::audit::Field, String)>)> {
        use crate::audit::Field as F;
        if self.stopping {
            return Vec::new();
        }
        self.stopping = true;
        self.console_sessions = console_sessions::Sessions::default();
        let mut records = vec![(
            "BROKER_STOPPING",
            vec![
                (F::BrokerInstanceId, self.instance.clone()),
                (F::Reason, "BROKER_STOPPING".into()),
            ],
        )];
        let instant = Instant::now();
        for r in self.pending.values() {
            // State Consumed, scheduler Running and non-Idle observations can
            // have crossed the irreversible claim. NEVER call those safe.
            if matches!(r.state, State::Pending | State::Approved)
                && r.execution_phase == ExecutionPhase::Idle
                && !r
                    .queue_state
                    .is_some_and(|s| s.terminal() || s == QueueState::Running)
                && instant < r.deadline
            {
                let mut fields = request_audit_fields(r);
                fields.retain(|(key, _)| *key != F::State);
                fields.push((F::State, "INVALIDATED".into()));
                fields.push((F::Reason, "BROKER_STOPPING".into()));
                records.push(("REQUEST_INVALIDATED", fields));
            }
        }
        records
    }
}
