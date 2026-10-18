# Best-effort failure semantics

Audit is best-effort diagnostics/history, not an authority or durable transaction participant. The API returns no authority-granting status. There is no persistent queue, retry thread, replay, buffering service, alternate database or stderr audit fallback.

Each record is encoded with fixed bounds, sent once through a fresh nonblocking native Unix datagram and discarded locally. Missing socket/permission denial, rejected/oversized record, EAGAIN/ENOBUFS/socket pressure or an interrupted send loses that record without changing authorization state. No unbounded send/retry wait or stderr pipe stall is introduced. A fresh socket/path lookup on each event permits recovery after Journald restarts without replaying old records.

Successful send means kernel acceptance, not durable journal storage. Journald can silently rate-limit, reject or lose records afterward (including full journal storage/rotation/daemon crash); the client has no durability acknowledgement. Disk-full after enqueue was not physically fault-injected; no losslessness claim follows from a successful send. Missing events never prove denial/nonexecution; approval alone never proves successful execution.

Shutdown handlers remain simple cancellation flags; the allocating logger is never called inside a signal handler. There is no logging queue to flush, and no claim the last record survives process/host failure. No filesystem execution, queue recovery or capability persistence is added.

Tests exercise an unavailable private socket and saturation; installed tests strengthen only the disposable broker sandbox with InaccessiblePaths for the journal socket, then verify a request still remains pending until explicit real PAM approval and executes despite missing broker audit records. Recovery is verified after removing that fixture. Per-unit rate limits are tightened (not disabled), actual journal JSON shows dropped view events while the request remains pending. No production service or security feature is disabled.

Mandatory durable audit would require a separate architecture/qualification decision. Do not reinterpret this implementation or the existing executor one-shot ledger as such a guarantee.
