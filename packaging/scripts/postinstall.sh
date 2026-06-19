#!/bin/sh
# Register the unit and lock down the config dir. Does NOT enable/start the
# service — the shipped config is a template that must be edited first.
set -e

chown -R nats-jwt-callout:nats-jwt-callout /etc/nats-jwt-callout 2>/dev/null || true
chmod 0750 /etc/nats-jwt-callout 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

cat <<'EOF'
nats-jwt-callout installed.
  1. Edit /etc/nats-jwt-callout/config.yaml (replace the REPLACE_ME values).
  2. Edit /etc/nats-jwt-callout/policy.yaml for your authorization rules.
  3. systemctl enable --now nats-jwt-callout
EOF
