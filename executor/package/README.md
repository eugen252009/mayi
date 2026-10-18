# Debian packaging reference

Current authoritative [build/development instructions](../../docs/development/DEVELOPMENT.md)
and [qualification index](../../docs/qualification/QUALIFICATION.md) replace the old candidate5
guide. [The exact former guide](../../docs/historical/baseline-3b6/executor/package/README.md)
is preserved as versioned history, not current PAM/session or ABI guidance.

[tpa.json](tpa.json) control.version is authoritative; native/Python component
versions are not product versions. [build-deb.sh](build-deb.sh) uses fresh native
targets, locked dependencies, deterministic timestamp handling, the packaged
_build_version stamp and [verify_abi.py](verify_abi.py). Dependencies, identities,
units and lifecycle scripts remain unchanged.

Release0.4.1-11 was built twice in the recorded Debian11 environment; observed
GLIBC ceiling2.30, declared supported ceiling2.31. Debian10 is not a supported
runtime/build qualification for this current release. Read the immutable bundle
BUILD.md for exact external prerequisites/tool/cache pins; do not infer
bare-host offline reproducibility from offline verification.

Do not rebuild/overwrite the qualified11 identity, install/restart services or
publish merely because these docs changed. Future packaging needs a concrete
change, version/qualification workflow and separate central handoff. Production
supports exact exec only; filesystem operations are not enabled.
