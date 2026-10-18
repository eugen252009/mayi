#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TPA_BIN=${TPA_BIN:-tpa}
OUT=${1:-"$ROOT/executor/target/debian"}
mkdir -p "$OUT"
VERSION=$(python3 "$ROOT/mayi/version.py")
ARTIFACT="$OUT/mayi_${VERSION}_amd64.deb"
if [ -e "$ARTIFACT" ] || [ -L "$ARTIFACT" ]; then
  echo "refusing to overwrite existing package identity $VERSION: $ARTIFACT" >&2
  exit 1
fi
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1792195200}
export SOURCE_DATE_EPOCH
NATIVE_TARGET=$(mktemp -d "$OUT/.mayi-native-target.XXXXXX")
TEMP_ARTIFACT=$(mktemp "$OUT/.mayi_${VERSION}_amd64.XXXXXX.deb")
cleanup() {
  rm -rf -- "$NATIVE_TARGET"
  rm -f -- "$TEMP_ARTIFACT"
}
trap cleanup EXIT HUP INT TERM
RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=$ROOT=/usr/src/mayi"
export RUSTFLAGS
cargo build --manifest-path "$ROOT/executor/Cargo.toml" --locked --release \
  --target-dir "$NATIVE_TARGET" \
  --bin mayi-executor --bin mayi-privileged-executor
PKGROOT="$ROOT/executor/target/debian/package-root"
rm -rf -- "$PKGROOT"
(
  cd "$ROOT"
  "$TPA_BIN" json < executor/package/tpa.json
)
rm -rf -- "$PKGROOT/usr/local"
mkdir -p "$PKGROOT/usr/bin" "$PKGROOT/usr/libexec/mayi" \
  "$PKGROOT/usr/share/doc/mayi" \
  "$PKGROOT/usr/lib/python3/dist-packages" \
  "$PKGROOT/usr/lib/systemd/system" "$PKGROOT/usr/lib/tmpfiles.d" \
  "$PKGROOT/usr/share/man/man1" "$PKGROOT/usr/share/man/man7" \
  "$PKGROOT/etc/pam.d"
install -m 0755 "$NATIVE_TARGET/release/mayi-executor" \
  "$PKGROOT/usr/bin/mayi-executor"
install -m 0755 "$NATIVE_TARGET/release/mayi-privileged-executor" \
  "$PKGROOT/usr/libexec/mayi/privileged-executor"
cp -a "$ROOT/mayi" "$PKGROOT/usr/lib/python3/dist-packages/mayi"
printf '%s\n' "$VERSION" > "$PKGROOT/usr/lib/python3/dist-packages/mayi/_build_version"
find "$PKGROOT/usr/lib/python3/dist-packages/mayi" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$PKGROOT/usr/lib/python3/dist-packages/mayi" -type f -exec chmod 0644 {} +
install -m 0755 "$ROOT/executor/package/usr/bin/mayi" "$PKGROOT/usr/bin/mayi"
install -m 0755 "$ROOT/executor/package/usr/bin/mayi-approve" "$PKGROOT/usr/bin/mayi-approve"
cp "$ROOT/executor/package/usr/lib/systemd/system/mayi-privileged-executor.service" \
  "$PKGROOT/usr/lib/systemd/system/mayi-privileged-executor.service"
cp "$ROOT/executor/package/usr/lib/systemd/system/mayi-broker.service" \
  "$PKGROOT/usr/lib/systemd/system/mayi-broker.service"
cp "$ROOT/executor/package/usr/lib/systemd/system/mayi-pam-auth.service" \
  "$PKGROOT/usr/lib/systemd/system/mayi-pam-auth.service"
cp "$ROOT/executor/package/usr/lib/tmpfiles.d/mayi.conf" "$PKGROOT/usr/lib/tmpfiles.d/mayi.conf"
install -m 0644 "$ROOT/executor/package/etc/pam.d/mayi-approve" "$PKGROOT/etc/pam.d/mayi-approve"
install -m 0644 "$ROOT/executor/package/usr/share/doc/mayi/copyright" \
  "$PKGROOT/usr/share/doc/mayi/copyright"
for doc in HISTORY_DESIGN HISTORY_SCHEMA HISTORY_CORRELATION HISTORY_SECURITY STATUS_DESIGN QUEUE_STATE_MAPPING STATUS_PROTOCOL STATUS_SECURITY STATUS_JSON_SCHEMA STATUS_WATCH_MODE CLI_DISPATCH_DESIGN CLI_COMPATIBILITY HISTORY_CLASSIFICATION HISTORY_EVENTS_MODE HISTORY_JSON_COMPATIBILITY BROKER_EPOCH RESTART_INVALIDATION UPDATE_PREFLIGHT PORTA_RECOVERY_CONTRACT EXECUTION_OUTCOME_SEMANTICS; do
  install -m 0644 "$ROOT/$doc.md" "$PKGROOT/usr/share/doc/mayi/$doc.md"
done
printf '%s\n' /etc/pam.d/mayi-approve > "$PKGROOT/DEBIAN/conffiles"
chmod 0644 "$PKGROOT/DEBIAN/conffiles"
install -m 0644 "$ROOT/man/mayi.1" "$PKGROOT/usr/share/man/man1/mayi.1"
install -m 0644 "$ROOT/man/mayi-workflow.7" "$PKGROOT/usr/share/man/man7/mayi-workflow.7"
gzip -n -9 "$PKGROOT/usr/share/man/man1/mayi.1"
gzip -n -9 "$PKGROOT/usr/share/man/man7/mayi-workflow.7"
find "$PKGROOT" -type d -exec chmod 0755 {} +
chmod 0644 "$PKGROOT/usr/lib/systemd/system/"*.service "$PKGROOT/usr/lib/tmpfiles.d/mayi.conf"
for script in postinst prerm postrm; do
  cp "$ROOT/executor/package/DEBIAN/$script" "$PKGROOT/DEBIAN/$script"
  chmod 0755 "$PKGROOT/DEBIAN/$script"
done
find "$PKGROOT" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
"$TPA_BIN" build -in="$PKGROOT" \
  -out="$TEMP_ARTIFACT"
python3 "$ROOT/executor/package/verify_abi.py" "$TEMP_ARTIFACT"
mv -- "$TEMP_ARTIFACT" "$ARTIFACT"
sha256sum "$ARTIFACT"
