# History security boundary

No broker or helper changes, root service, setuid bit, sudo/polkit rule, group/ACL modification, authentication cache renewal or journal-read privilege. The calling UID reads the system journal under existing OS permissions. Partial/inaccessible-journal warnings are errors (13), not an empty successful history. The command never auto-elevates. Full-system journal read rights may expose security metadata; obtain any permission changes separately through the operator's normal policy, never automatically.

Fixed /usr/bin/journalctl, no shell, fixed early unit/UID/transport/schema filters. Bounded timestamp argument and strict queue ID; no untrusted executable/pager/environment injection. The viewer projects only allowlisted typed metadata, not arbitrary journal messages. Invalid fields/arrays, control-bearing names, excessive lengths and timestamps are skipped with counts. Human output is ASCII-escaped/wrapped; JSON uses ensure_ascii. No credentials, command arguments, output or capability/session/view secrets are returned.

Emitters: broker UID 23002 in mayi-broker.service; root in mayi-pam-auth.service / mayi-privileged-executor.service. These are existing fixed deployment identities. Third-party local processes cannot forge kernel _UID/unit attribution through user fields; root or compromised emitters remain outside any tamper-proof claim.

Current broker state is never queried or inferred from retained nonterminal records. No capability persistence, replay or filesystem execution. Existing source/installed regressions must still pass; qualification reports record results separately, not assumed from this design.
