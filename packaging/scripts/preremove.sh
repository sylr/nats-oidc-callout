#!/bin/sh
# Stop and disable the service on full removal (not on upgrade).
#   deb: $1 = "remove" (uninstall) | "upgrade"
#   rpm: $1 = 0 (uninstall)        | 1 (upgrade)
set -e

if [ "$1" = "remove" ] || [ "$1" = "0" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now nats-jwt-callout >/dev/null 2>&1 || true
    fi
fi
