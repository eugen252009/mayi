# Exclusive queue snapshot mapping

Order is deliberate. Each retained request counts in at most one active category; synchronous observations with a retained request are deduplicated.

| Counter | Meaning |
|---|---|
| pending_approval | State Pending, effective request deadline not reached; includes queued and synchronous proposals regardless of unapproved dependencies |
| waiting_dependency | Approved queued request with any prerequisite missing or not SUCCEEDED, including a failed dependency not yet terminalized by normal scheduler housekeeping |
| approved_ready | Approved queued request with all prerequisites SUCCEEDED (or none), not dispatched |
| awaiting_consumption | Approved synchronous request awaiting its requester consume |
| dispatching | Claimed execution, actual start not yet observed; queued phase or synchronous in-flight map |
| running | Actual successful spawn notification observed and final correlated RPC outcome not yet observed |
| total_active | Sum of the six exclusive categories, distinct retained requests/in-flight synchronous calls |
| blocked_terminal | Retained QueueState Blocked, outside active total |
| outcome_unknown_terminal | Retained queued ExecutionUnknown, outside active total; residual effects may still run |

Queue terminal SUCCEEDED/FAILED/DENIED/EXPLAIN_REQUESTED/EXPIRED/BLOCKED/EXECUTION_UNKNOWN are not active. Standalone denied/explained/expired/consumed-with-finished-execution are not active. Effective monotonic expiration is excluded without changing stored state or emitting expiry events. Already-dispatched execution is not expiration-canceled. State Ready/WaitingDependency uses actual prerequisites in the same snapshot rather than assuming the scheduler already updated its label.

An unapproved job with a failed prerequisite still needs a decision in the current broker model, so it is pending, not double-counted as waiting. After approval, normal scheduling may turn it terminal BLOCKED; status never performs that transition. Shared prerequisites/multiple views never add rows. Dependency cycles remain rejected by existing submission validation. There is no cancellation protocol: no canceled/cancellation-pending counter or fictional transition.

The root executor is serial; multiple QueueState Running entries can mean one actual child plus a backlog. That is why dispatching is separate. No live console connection/authentication count is inferred from a socket file or process. Restart clears broker/observation state without replay; old dispatched effects may continue, so empty fresh broker state is not proof the host has no residual work.
