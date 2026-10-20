> Archive view: maintainer-local paths have been omitted. Commands containing
> `[local-only path omitted]` are historical records, not runnable instructions.
> Original bytes remain at the commit/path recorded by the documentation checker.

# Local UI testing / rollback — not performed, explicit authorization required

Stable host remains Mayi0.4.1-10. Do not install or restart merely because isolated qualification passes. Coordinate/reconcile active or uncertain work first: preflight is only a snapshot, not an admission lock.

Candidate:
[local-only path omitted]
SHA256 57a1f4d3aea949e7926db7d1e67898a2ec502713314a615171b76257d1ee7e12.
Verify SHA256, dpkg-deb -f Package/Version/Architecture/Depends and the existing verify_abi.py before any separately authorized replacement. The exact version must be0.4.1-11~ui2, amd64, not a rebuilt substitute.

ONLY AFTER explicit operator authorization, keep mayi-approve in the human's own interactive TTY and submit the exact supported operation once:

```sh
mayi /usr/bin/systemd-run --unit=mayi-ui11-validation --collect --no-block --property=Type=oneshot /usr/bin/dpkg -i [local-only path omitted]
```

This restarts the executor/broker/PAM services, invalidates old authorizations and can lose an originating response. Submission success is not installation success. Do not auto-repeat ambiguous results. Read unit journal/result plus dpkg-query and dpkg -V independently. Then manually check --version/help, compact status, --details, unchanged --json, --watch resize/interrupt, --watch --plain, request/events history and a separately human-approved harmless operation. Do not crash-test the active host or automate real PAM credentials.

Verified rollback copy:
[local-only path omitted]
SHA256 d614a44cc9a3106dacfbabac7d6204cc8ace77fe434722804bc3e6a918d3e4f1.

ONLY under separate rollback authorization:

```sh
mayi /usr/bin/systemd-run --unit=mayi-ui11-rollback --collect --no-block --property=Type=oneshot /usr/bin/dpkg -i [local-only path omitted]
```

Verify completion, version0.4.1-10, dpkg -V and all three services independently. Both versions retain native schema1, history JSON2, live snapshot1 and epoch-bound IDs; rollback restores older human formatting and does not make old authority reusable. Private production provenance/epoch policy and conservative outcomes are unchanged. No local installation or rollback was executed by this task.
