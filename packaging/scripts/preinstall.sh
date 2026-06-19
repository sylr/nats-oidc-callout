#!/bin/sh
# Create the system user/group the service runs as. Runs before files are
# unpacked (deb preinst / rpm %pre), so file ownership set by the package
# applies cleanly.
set -e

if ! getent group nats-jwt-callout >/dev/null 2>&1; then
    groupadd --system nats-jwt-callout
fi

if ! getent passwd nats-jwt-callout >/dev/null 2>&1; then
    useradd --system --gid nats-jwt-callout \
        --home-dir /var/lib/nats-jwt-callout --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "NATS auth callout service" \
        nats-jwt-callout
fi
