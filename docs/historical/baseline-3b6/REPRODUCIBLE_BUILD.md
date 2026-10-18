# Reproducible candidate

Verified ordering:0.4.1-10 <0.4.1-11~ui1 <0.4.1-11~ui2 <0.4.1-11.
Two independent clean Debian11 builds, fresh Cargo targets/output directories, locked offline dependencies, SOURCE_DATE_EPOCH1792195200. Rust/Cargo1.95.0, GCC10.2.1, GLIBC2.31-13+deb11u14. Existing qualified TPA tool SHA2564da9418be15d2d5e212e21ff399a33519ca342522633afaed6341705765370a7; no TPA source/configuration changes.

Byte-identical final candidate/reproduction; mandatory ABI/dependency/hardening gate PASS, observed GLIBC ceiling2.30 within2.31. Root-owned payload, no setuid/setgid, pyc or private key; exact package/version/architecture verified. Privileged executor remains byte-identical to stable. Debug tests use a freshly built current executable, not a stale prerequisite.

ui1 package f25886d3... remains immutable/rejected; ui2 has a new full hash recorded below. No qualified old package was overwritten or stable release rebuilt. No signing/tagging/publication.

Version0.4.1-11~ui2; runtime/package-input source574a63dd05c70656e4014b363ae06afa75c1f273 (unsigned intentionally; signing forbidden). SHA25657a1f4d3aea949e7926db7d1e67898a2ec502713314a615171b76257d1ee7e12. Evidence /home/eugen/projekte/mayi-qualification/ux-0.4.1-11-ui2.
