#!/bin/sh
set -e

# Substitute secrets into the config template at startup.
# TURN_EXTERNAL_IP is provided by Fly.io (the machine's dedicated IPv4).
# TURN_SHARED_SECRET is a Fly.io secret set via: fly secrets set TURN_SHARED_SECRET=...

if [ -z "$TURN_EXTERNAL_IP" ]; then
  # Auto-detect public IP if not provided
  TURN_EXTERNAL_IP=$(curl -sf https://checkip.amazonaws.com || \
                     curl -sf https://api.ipify.org)
fi

if [ -z "$TURN_SHARED_SECRET" ]; then
  echo "ERROR: TURN_SHARED_SECRET is not set" >&2
  exit 1
fi

sed -e "s/__TURN_EXTERNAL_IP__/$TURN_EXTERNAL_IP/g" \
    -e "s/__TURN_SHARED_SECRET__/$TURN_SHARED_SECRET/g" \
    /etc/coturn/turnserver.conf.tmpl > /etc/coturn/turnserver.conf

exec turnserver -c /etc/coturn/turnserver.conf "$@"
