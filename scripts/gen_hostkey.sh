#!/usr/bin/env bash
# Generate a fresh SSH host key for the SSH honeypot. Reused keys are one of
# the strongest signals Censys uses to tag honeypots, so rotate at deploy time
# and periodically thereafter.
set -euo pipefail

KEY_DIR="$(dirname "$0")/../services/ssh/host_key"
mkdir -p "$KEY_DIR"
KEY_PATH="$KEY_DIR/ssh_host_rsa_key"

if [[ -f "$KEY_PATH" ]]; then
    echo "Rotating existing key -> ${KEY_PATH}.old"
    mv "$KEY_PATH" "${KEY_PATH}.old"
fi

ssh-keygen -t rsa -b 2048 -f "$KEY_PATH" -N "" -C "" -q
echo "New SSH host key written: $KEY_PATH"
echo "Fingerprint:"
ssh-keygen -lf "$KEY_PATH"
