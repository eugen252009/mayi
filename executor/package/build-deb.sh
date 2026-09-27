#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TPA_BIN=${TPA_BIN:-tpa}
OUT=${1:-"$ROOT/executor/target/debian"}
mkdir -p "$OUT"
cargo build --manifest-path "$ROOT/executor/Cargo.toml" --locked --release \
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
install -m 0755 "$ROOT/executor/target/release/mayi-executor" \
  "$PKGROOT/usr/bin/mayi-executor"
install -m 0755 "$ROOT/executor/target/release/mayi-privileged-executor" \
  "$PKGROOT/usr/libexec/mayi/privileged-executor"
cp -a "$ROOT/mayi" "$PKGROOT/usr/lib/python3/dist-packages/mayi"
find "$PKGROOT/usr/lib/python3/dist-packages/mayi" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$PKGROOT/usr/lib/python3/dist-packages/mayi" -type f -exec chmod 0644 {} +
install -m 0755 "$ROOT/executor/package/usr/bin/mayi" "$PKGROOT/usr/bin/mayi"
install -m 0755 "$ROOT/executor/package/usr/bin/mayi-approve" "$PKGROOT/usr/bin/mayi-approve"
cp "$ROOT/executor/package/usr/lib/systemd/system/mayi-privileged-executor.service" \
  "$PKGROOT/usr/lib/systemd/system/mayi-privileged-executor.service"
cp "$ROOT/executor/package/usr/lib/systemd/system/mayi-broker.service" \
  "$PKGROOT/usr/lib/systemd/system/mayi-broker.service"
cp "$ROOT/executor/package/usr/lib/tmpfiles.d/mayi.conf" "$PKGROOT/usr/lib/tmpfiles.d/mayi.conf"
install -m 0644 "$ROOT/executor/package/etc/pam.d/mayi-approve" "$PKGROOT/etc/pam.d/mayi-approve"
install -m 0644 "$ROOT/executor/package/usr/share/doc/mayi/copyright" \
  "$PKGROOT/usr/share/doc/mayi/copyright"
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
"$TPA_BIN" build -in="$PKGROOT" \
  -out="$OUT/mayi_0.4.1-1_amd64.deb"
sha256sum "$OUT/mayi_0.4.1-1_amd64.deb"
