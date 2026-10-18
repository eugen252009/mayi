# Approval UI development candidate

Version: 0.4.1-9~ui1, based on qualified commit 5b8f62ba5d2e41d1998aea286674b8285fa44f54. No package or release qualification is implied.

## Existing workflow inspected
Rust broker.rs renders the persistent terminal console; no TUI framework. LIST_PENDING supplies exec rows, requester UID, expiry, IDs, digests and dependencies. GET_CHALLENGE and a correlated view precede each decision. Decisions pass the controlling-terminal descriptor to the broker for per-decision PAM authentication. The local entry checks interactive descriptors and approver-group membership; it is not a cached PAM login. Space already toggled IDs; command paths/argv were previously always verbose. Python CLI polls request status separately. Console is interactive-only; request/status integrations retain their schemas.

## Implemented
A presentation-only approval_ui.rs renders derived basenames, neutral action descriptions, requester/privileged identity, state, bounded argument previews, one-time consumption semantics, and available expiry. Space expands the complete original row as escaped JSON, with indexed arguments preserved in the array. Brackets page in either view. Pagination bounds emitted data, not total input (already bounded by protocol). Dimensions are queried on navigation and each input polling tick. ASCII-only chrome, no colors or hidden cursor. No framework or dependency added.

Pages indicate that more information exists. Allow ALL still applies to the displayed request set, not merely the visible page. Do not confuse opening details with granting permission.

## Examples (80-column excerpts; page totals depend on height)
Before:
```
MAYI / Review commands
Executor: UID 0 / GID 23012 (privileged)
[0] /usr/bin/bash [argv0=bash] (PENDING_APPROVAL)
     -c
     'echo hello'
```
After:
```
MAYI / Approval
Page 1/2; 1 request(s)
[0] Program: bash
Action: Execute program with arguments
Requester UID: 1001 | privileged UID 0 / GID 23012
State: PENDING_APPROVAL
CAUTION: interpreter/wrapper; supplied code or programs may run.
Arguments: 3 (including argv[0]); preview:
  argv[0]: bash
  argv[1]: -c
  argv[2]: 'echo hello'
[Space] Show technical details
[ / ]: page
[a] Allow ALL pending; [d] Deny; [f] Follow-up
[s] Skip; [q] Quit; digits: subset
Action + Enter (no default):
```
Expanded (paged excerpt):
```
More information: exact broker fields (JSON notation)
  "operations": [
    {
      "argv": ["bash", "-c", "echo hello"],
      "executable": "/usr/bin/bash",
      "type": "exec"
    }
  ]
[Space] Hide technical details
```
Actual JSON uses pretty-printed arrays on separate lines. Other fields remain present, including dependencies, identifiers, requester and expiration.

Remaining UX limitations: wrapping may split escape notation; chrome can exceed extremely short terminal heights. Unknown wrappers cannot be exhaustively identified. Large sets require pagination; no mandatory read-all gate is introduced.
