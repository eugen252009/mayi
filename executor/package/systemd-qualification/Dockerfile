ARG DEBIAN_SUITE=trixie
FROM debian:${DEBIAN_SUITE}
ARG DEBIAN_SUITE
ENV DEBIAN_FRONTEND=noninteractive
RUN if [ "$DEBIAN_SUITE" = buster ]; then \
      printf '%s\n' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20240612T000000Z buster main' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20240612T000000Z buster/updates main' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20240612T000000Z buster-updates main' \
        > /etc/apt/sources.list; \
      printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99snapshot; \
    elif [ "$DEBIAN_SUITE" = bullseye ]; then \
      printf '%s\n' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260824T000000Z bullseye main' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20260824T000000Z bullseye-security main' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260824T000000Z bullseye-updates main' \
        > /etc/apt/sources.list; \
      printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99snapshot; \
      mkdir -p /etc/ssl/certs; \
    fi \
 && apt-get update -qq \
 && apt-get install -y -qq systemd systemd-sysv dbus python3 adduser init-system-helpers util-linux procps iproute2 ca-certificates \
 && rm -f /usr/sbin/policy-rc.d \
 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
