//! Read-only aggregate projection under the existing broker mutex.
use super::*;

impl Broker {
    pub(super) fn queue_snapshot(&self) -> Value {
        let instant = Instant::now();
        let snapshot_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64);
        let Ok(snapshot_unix_ms) = snapshot_unix_ms else {
            return response_error("CLOCK_UNAVAILABLE", "snapshot clock unavailable");
        };
        let ids: HashMap<&str, &Request> = self
            .pending
            .values()
            .filter_map(|r| r.request_id.as_deref().map(|id| (id, r)))
            .collect();
        let (mut pending, mut dependency, mut ready, mut consume, mut dispatching, mut running) =
            (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
        let (mut blocked, mut unknown) = (0u64, 0u64);
        for phase in self.synchronous_executions.values() {
            match phase {
                ExecutionPhase::Started => running += 1,
                ExecutionPhase::Dispatching => dispatching += 1,
                _ => {}
            }
        }
        for r in self.pending.values() {
            if r.queue_state.is_none() && self.synchronous_executions.contains_key(&r.challenge) {
                continue;
            }
            if r.queue_state == Some(QueueState::Blocked) {
                blocked += 1;
                continue;
            }
            if r.queue_state == Some(QueueState::ExecutionUnknown) {
                unknown += 1;
                continue;
            }
            if r.queue_state.is_some_and(QueueState::terminal) {
                continue;
            }
            if r.execution_phase == ExecutionPhase::Started {
                running += 1;
                continue;
            }
            if r.execution_phase == ExecutionPhase::Dispatching {
                dispatching += 1;
                continue;
            }
            if instant >= r.deadline {
                continue;
            } // effective expiry, no mutation/sweep
            if r.state == State::Pending {
                pending += 1;
            } else if r.state == State::Approved {
                if r.queue_state.is_none() {
                    consume += 1;
                } else if r.dependencies.iter().any(|id| {
                    ids.get(id.as_str())
                        .is_none_or(|dep| dep.queue_state != Some(QueueState::Succeeded))
                }) {
                    dependency += 1;
                } else {
                    ready += 1;
                }
            }
        }
        json!({"ok":true,"protocol":VERSION,"response_to":"QUEUE_STATUS","schema_version":1,
            "broker":"ONLINE","broker_instance_id":self.instance,"snapshot_unix_ms":snapshot_unix_ms,
            "scope":"approver_global_aggregate","pending_approval":pending,"waiting_dependency":dependency,
            "approved_ready":ready,"awaiting_consumption":consume,"dispatching":dispatching,"running":running,
            "total_active":pending+dependency+ready+consume+dispatching+running,
            "blocked_terminal":blocked,"outcome_unknown_terminal":unknown})
    }
}
