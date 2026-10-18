# Performance and bounds

Representative synthetic stream offers 1,000,000 events / 200,000 identities through an independent producer process. The reader intentionally stops at 20,000 events, rather than consuming a million records. Tested pipeline: decode/read 0.433 s; derive/sort 0.111 s; JSON serialization 0.036 s; output 5,746,380 bytes, peak parent RSS 47,192 KiB. 2,000 identities returned, 10,000 events omitted by identity cap, scan_truncated=true. Raw input read 11,129,971 bytes (pipe chunk boundaries can change this). Source benchmark and JSON: /home/eugen/projekte/mayi-qualification/history-0.4.1-10-journald6/benchmark.py, performance-final.json.

This measures the bounded reader/reconstruction/serialization, not actual production journal disk/index latency or a full million-record traversal. Actual installed native journal tests collect 248 events per guest and verify indexed native filters, not production-scale performance. No production SLA is inferred.

Limits: 20,000 native records, 16 MiB input, 64 KiB line, 20 s wall deadline, 2,000 identities. O(bounded records) maps and bounded per-group sorting; no growing daemon/cache/database. stdout/stderr pipes drained concurrently, bounded stderr, child cleanup on cancellation/timeout. --limit bounds presentation; --all exposes all identities within these limits, not unlimited journal export.

The scan is one reverse filtered journalctl invocation, not repeated whole-journal scans. IDs are canonical; malformed data is skipped with counts. An explicit request outside the bounded window may be absent even if physically retained: use direct journalctl MAYI_REQUEST_ID=... (and explicit helper bridges) for older exports. --since narrows the selected time window but cannot retrieve records older than a newer full scan cap. Completeness/omission metadata remains essential.


Package runtime/source commit: c511c7f948e4b811baec9e83976fec6ec5b898ba. Version: 0.4.1-10~journald6 amd64. Package and independent rebuild SHA-256: 7149d79e8aec0f8a7c119a9f8aa0f9ede00f7120cd2674c6b3754d2d8bccb51a.
