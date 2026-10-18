# Declared limits

All demonstrated HIGH/MEDIUM findings and ui1's zero-size watch defect are resolved. These remain explicit scope limits:
- Supported same-screen approval matrix starts at30x8. Smaller terminals should be resized; unknown physical geometry uses positive80x24 fallback, not an assertion about physical viewport.
- Detailed ANSI watch refuses a non-fitting canvas, restores screen then explains --plain/resize. Plain/no-ANSI output and full diagnostic dumps intentionally use scrollback.
- History nonce prefixes are abbreviations, not globally unique proof or valid lookup tokens; full identifiers, dates and signal details remain in JSON/request evidence.
- Request origin application name is not authenticated metadata. UI shows requester UID plus exact target path/argv, not invented labels/effects.
- Pre-existing explicit standalone development mode uses an ephemeral provenance key. Do not deploy that flag or expect cross-restart ID authentication there; production strict persistent-key/epoch policy remains.
- Stock Debian11/12/13 amd64 only; custom PAM/MFA/SSSD/physical suspend outside scope. Best-effort journal, no queue/capability recovery, start-time TTL or general exactly-once side effects. Filesystem executor DISCONNECTED / INCOMPLETE.
- Original failed ui1 and ui2 fixture processes remain recorded, with new-version correction or strict same-artifact acknowledged-input retry as applicable; no favourable relabelling.

No host installation/restart or release-infrastructure change is authorized by this qualification.

Version0.4.1-11~ui2; runtime/package-input source574a63dd05c70656e4014b363ae06afa75c1f273 (unsigned intentionally; signing forbidden). SHA25657a1f4d3aea949e7926db7d1e67898a2ec502713314a615171b76257d1ee7e12. Evidence /home/eugen/projekte/mayi-qualification/ux-0.4.1-11-ui2.
