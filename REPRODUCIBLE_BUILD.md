# Reproducible development package

PASS: two builds from identical source archive (commit c511c7f948e4b811baec9e83976fec6ec5b898ba), separate output directories, separate fresh Cargo release targets, existing Mayi build-deb.sh and exact TPA tool. Locked offline Cargo inputs; no host-native/stale release binaries. Second package retained as /home/eugen/projekte/mayi-qualification/history-0.4.1-10-journald6/reproduced.deb.

Debian 11 builder child overlay, Rust/Cargo 1.95.0, GCC 10.2.1, GLIBC 2.31; SOURCE_DATE_EPOCH=1792195200. Existing TPA executable pin 4da9418be15d2d5e212e21ff399a33519ca342522633afaed6341705765370a7. Compiler/package tool environment inherited from reviewed qualification builder and recorded in builder/environment.txt. Exact builder process argv is in builder/executor-command.json (VM storage remains in candidate5 builder directory); source6 and fresh-target build logs here.

Both artifacts SHA-256 7149d79e8aec0f8a7c119a9f8aa0f9ede00f7120cd2674c6b3754d2d8bccb51a; cmp PASS. Mandatory ABI checker runs before atomic final artifact rename in each existing build invocation. Host copy SHA equals builder first/second and installed VM-payload bytes. No rebuilding/overwriting previous journald4/5 identities. Reproducibility is within the recorded toolchain, not an independent compiler bootstrap or new source/release signature.

Evidence: source.tar, builder/build-twice.log/.exit, package-sha256.txt, candidate.deb, reproduced.deb, abi.json, package-validation.json. Later report-only commits do not change packaged runtime/build inputs or the four installed design/schema/security/correlation documents.


Package runtime/source commit: c511c7f948e4b811baec9e83976fec6ec5b898ba. Version: 0.4.1-10~journald6 amd64. Package and independent rebuild SHA-256: 7149d79e8aec0f8a7c119a9f8aa0f9ede00f7120cd2674c6b3754d2d8bccb51a.
