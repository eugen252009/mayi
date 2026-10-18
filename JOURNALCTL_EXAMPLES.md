# Journalctl examples

Run read-only with existing journal-reader privileges. No sudo/group/ACL changes are part of this feature. These commands were exercised against installed Debian 11/12/13 guests (systemd 247/252/257) with synthetic requester UID 24701. Replace it with 1000 as appropriate after a separately authorized installation.

All native Mayi records (add trusted unit constraints for attribution):
```sh
journalctl SYSLOG_IDENTIFIER=mayi -o short-iso
journalctl -F MAYI_EVENT
```

Bare field-existence syntax `journalctl MAYI_EVENT` is rejected with Invalid argument on all three tested versions. SYSLOG_IDENTIFIER=mayi is the compatible native Mayi stream query, not a retroactive conversion of old MESSAGE text.

```sh
journalctl _SYSTEMD_UNIT=mayi-broker.service MAYI_EVENT=QUEUE_EXECUTION_FINISHED MAYI_STATE=SUCCEEDED
journalctl _SYSTEMD_UNIT=mayi-broker.service MAYI_EVENT=QUEUE_EXECUTION_FINISHED MAYI_STATE=FAILED
journalctl _SYSTEMD_UNIT=mayi-broker.service MAYI_EVENT=QUEUE_DISPATCH_FAILED
journalctl _SYSTEMD_UNIT=mayi-broker.service MAYI_REQUEST_ID="$REQUEST_ID" -o json-pretty
journalctl _SYSTEMD_UNIT=mayi-broker.service MAYI_REQUESTER_UID=1000 -o short-iso
journalctl _SYSTEMD_UNIT=mayi-privileged-executor.service MAYI_EXECUTION_ID="$EXECUTION_ID" -o json-pretty
```

The test harness records exact queries, exit codes and raw JSON for success/failure/request/requester/executor/PAM filters. Signals appear on actual executor records as MAYI_CHILD_SIGNAL, not a fake exit code. Unknown results use *_OUTCOME_UNKNOWN, not FINISHED. Field absence is meaningful; record absence may also be loss/rate limiting. RQ-only scope and cross-service join are explained in REQUEST_CORRELATION.md.

No mayi history command was added. A future read-only wrapper should reuse journalctl as the caller and preserve existing journal access restrictions; it must not create a privileged history endpoint, auto-elevate access or become a capability recovery/replay path.

The operator's installed UI4 package is not replaced by this task, so these native fields are not retroactively present on its historical service messages.
