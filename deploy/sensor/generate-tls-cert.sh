#!/usr/bin/env bash
# Generate a self-signed TLS cert for honeypot product spoofing.
# Censys/Shodan don't care about cert validity — they just need TLS handshake.
# DOES NOT TOUCH SSH. Only creates cert files.
set -euo pipefail

CERT_DIR="${1:-/opt/honeyforge/deploy/sensor/certs}"
mkdir -p "$CERT_DIR"

# Generate if not exists
if [ ! -f "$CERT_DIR/honeypot.key" ]; then
    echo "Generating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CERT_DIR/honeypot.key" \
        -out "$CERT_DIR/honeypot.crt" \
        -days 3650 \
        -subj "/C=US/ST=CA/O=Fortinet/CN=FortiGate" \
        2>/dev/null
    chmod 644 "$CERT_DIR/honeypot.crt"
    chmod 600 "$CERT_DIR/honeypot.key"
    echo "  ✓ Cert: $CERT_DIR/honeypot.crt"
    echo "  ✓ Key:  $CERT_DIR/honeypot.key"
else
    echo "  ✓ TLS cert already exists"
fi
