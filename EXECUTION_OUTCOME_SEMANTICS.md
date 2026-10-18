# Authorization is not execution outcome

An epoch transition invalidates old authorization, not completed side effects.
Consumed/dispatching/running requests can have residual work after broker death.
No response, UNKNOWN and a stopped service do not prove cancellation or failure.
Native spawn observation distinguishes dispatch from actual child start.
Definitive correlated completion remains success/failure across epochs.

The three services are separate systemd units. Broker restart kills its worker
threads and in-memory state, not the separately supervised executor or PAM
service. Executor children can survive broker-only restart and finish after a
new broker starts. Old PAM conversations may finish or time out, but their
responses cannot recreate state or match a new epoch/session/challenge.
Console sessions disappear with their broker; authentication is per process.

Debian postinst restarts privileged executor, then broker, then PAM service.
prerm removal stops broker, PAM, then executor; upgrade does not drain requests.
Default systemd control-group termination can kill executor children on executor
restart. Self-upgrade may lose the original broker/executor response even when
dpkg later completes; service supervision and package version must be verified
independently. This task does not change that lifecycle order or introduce an
upgrade/restart endpoint. The only unit change is private StateDirectory storage
for the non-authorizing request-ID provenance key; purge removes that storage.

A clean shutdown records safe pre-claim invalidation where proven. Abrupt death
does not; history can infer old epoch authorization invalidity from later
lifecycle evidence but leaves execution UNKNOWN and reconciliation required.
History never queries the live broker or restores queue/session/capability state.
Filesystem execution remains disconnected/incomplete.
