# mayi

`mayi` is an unprivileged proposal/inspection prototype. Protocol 5 establishes a Rust-owned request/challenge/approval lifecycle, but **filesystem execution remains disabled** and the trusted human-facing approval application is not yet complete.

## Inspect

```sh
python -m mayi.cli inspect 'echo hello > /etc/example.conf'
python -m mayi.cli check 'echo hello > /etc/example.conf'
```

Python parsing, adapters and policy are advisory. A Python client may propose one modeled filesystem operation to the Rust request socket; it cannot supply an approval, choose a challenge ID, or modify a request after storage. Client SHA-256 values are never authorization.

## Protocol-v5 broker

The broker requires separate requester, broker, and approver UIDs plus separate request/approval socket groups:

```sh
mayi-executor --request-socket /run/mayi/request.sock \
  --request-uid REQUEST_UID --request-gid REQUEST_GID \
  --approval-socket /run/mayi/approval.sock \
  --approval-uid APPROVER_UID --approval-gid APPROVAL_GID
```

The broker refuses EUID 0, requires requester/broker/approver UIDs and production socket groups to be distinct, and rejects a same-UID requester unless `--development-same-uid` is explicitly selected. Socket files are broker-owned, mode 0660, and assigned to their configured role groups. Socket parent directories must be broker-owned and non-writable by group/other; ancestors must be root/broker-owned and non-writable, except root-owned sticky directories such as `/tmp`. Production provisioning must ensure only the intended requester/approver is in each role group. The Rust console is launched with `--approval-console --approval-socket PATH --broker-uid BROKER_UID`; it requires an interactive unprivileged TTY and checks broker/request/challenge/digest/view correlations before displaying or deciding.

Each fetch creates a fresh broker-generated, single-use view bound to the broker instance, exact challenge, request digest, approver UID, and expiry. A later fetch replaces the earlier view; approve, deny, and explain consume it. The view ID is sent only over the approval socket; audit logs contain its SHA-256 reference, not the ID. The server uses separate bounded request/approval worker pools (8 connections each), a five-second transaction deadline, and rejects excess connections rather than queueing without bound. Same-UID development mode does not provide OS process isolation. Cross-UID end-to-end qualification was not completed in this environment; this milestone remains incomplete, and the console/deployment are not independently certified.

Rust generates a 192-bit random broker ID and unique unpredictable challenge IDs, stores immutable requests in bounded ephemeral memory, renders challenges from broker-held data, and owns expiry/decisions. Restart invalidates all challenges. Protocol 4 client approval fields are rejected. Stdio is validation-only and cannot create challenges or approval state.

Even after approval, the internal consume lifecycle returns `EXECUTION_DISABLED`. FilePatch/FileCreate/FileDelete/FileMove cannot mutate. Exec, service/package operations, fake-root and real-root execution remain disabled. No sudo, setuid, capabilities, or host-file changes are part of this project state.

See `PROTOCOL.md`, `SECURITY_BOUNDARY.md`, and `ARCHITECTURE.md`. This approval-ceremony hardening milestone is incomplete pending distinct-UID deployment qualification and end-to-end console/socket-substitution testing. The dormant filesystem executor has separate unresolved race and topology findings.
