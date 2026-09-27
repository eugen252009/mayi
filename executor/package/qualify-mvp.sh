#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OLD="$ROOT/executor/target/debian/mayi_0.2.0_amd64.deb"
NEW="$ROOT/executor/target/debian/mayi_0.2.1_amd64.deb"
[ -f "$OLD" ] || { echo "missing upgrade baseline package: $OLD" >&2; exit 2; }
[ -f "$NEW" ] || { echo "build the TPA package first: $NEW" >&2; exit 2; }
printf '%s  %s\n' 685632ff860e1efe1a55adf7af99b3d82446755875936d3aa8bf5e978635ef9d "$OLD" | sha256sum -c -
PREFIX="mayi-role-qual-$$"
UPGRADE="$PREFIX-upgrade"
FRESH="$PREFIX-fresh"
cleanup() {
    docker rm -f "$UPGRADE" "$FRESH" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
prepare_container() {
    name=$1
    docker run -d --name "$name" --network bridge --security-opt no-new-privileges debian:trixie sleep infinity >/dev/null
    docker cp "$OLD" "$name:/tmp/mayi_0.2.0_amd64.deb"
    docker cp "$NEW" "$name:/tmp/mayi_0.2.1_amd64.deb"
    docker exec "$name" apt-get update -qq
    docker exec --env DEBIAN_FRONTEND=noninteractive "$name" apt-get install -y -qq adduser python3 >/dev/null
    docker network disconnect bridge "$name"
    topology=$(docker inspect --format '{{.HostConfig.Privileged}}|{{len .Mounts}}|{{len .NetworkSettings.Networks}}' "$name")
    [ "$topology" = "false|0|0" ] || { echo "unsafe Docker qualification topology ($name): $topology" >&2; exit 1; }
}

prepare_container "$UPGRADE"
MAYI_TEST_CONTAINER="$UPGRADE" MAYI_TEST_MODE=upgrade python3 "$ROOT/executor/package/qualify-mvp.py"
prepare_container "$FRESH"
MAYI_TEST_CONTAINER="$FRESH" MAYI_TEST_MODE=fresh python3 "$ROOT/executor/package/qualify-mvp.py"
