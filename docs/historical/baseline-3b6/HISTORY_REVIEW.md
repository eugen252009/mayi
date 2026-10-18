# Initial history review

H1 MEDIUM: three different authentic-format IDs in one epoch display identically as rq_v2_bbbbbbbbb... because first18 characters are epoch-prefix data. Reproduction audit/history-same-epoch.txt/.json. Fix human-only abbreviated identity using the random request nonce rather than epoch prefix; clearly label abbreviations and keep full IDs in JSON/detail. Do not accept abbreviated IDs as authority or lookup identifiers.

H2 LOW: PENDING? is footnoted historical, but still looks actionable; RESULT is the Mayi code, not necessarily child exit. Human-only improvement: UNKNOWN for unconfirmed outcome with explicit no-live-query guidance; label Mayi/child codes separately. Preserve JSON status, observed_state, epoch_id, recovery fields and existing filters. Acceptance same JSON documents and real/diagnostic distinction, historical outcomes not rewritten, unknown/incomplete never success.

Epoch labels/separators are already virtual and state no live broker query. Keep recorded order, legacy UNKNOWN epochs, full request/challenge details, --limit/--all/--epoch filters, bounded scans and permission errors. No new database, live endpoint or pagination authority.
