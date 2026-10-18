# Filesystem executor — DISCONNECTED / INCOMPLETE

The live broker rejects non-exec structured filesystem proposals with
UNSUPPORTED_OPERATION before pending admission. They cannot be approved/queued/
consumed through the enabled production path. Historical direct-core or retired
consume examples mentioning EXECUTION_DISABLED do not establish live support.

[filesystem.rs](../executor/src/filesystem.rs), fixtures and regression tests remain
preserved; do not remove tests, connect the core or infer qualification from their
presence. [Historical research](history/README.md), [test isolation](TEST_ISOLATION.md)
and [current limits](LIMITATIONS.md) explain scope. The former status text is
[preserved verbatim](historical/baseline-3b6/docs/FILESYSTEM_EXECUTOR_STATUS.md).
