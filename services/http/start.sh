#!/bin/sh
# Start the HTTP honeypot — with TLS if certs are mounted, plain HTTP otherwise.
# DOES NOT TOUCH SSH.

CERT="/app/certs/honeypot.crt"
KEY="/app/certs/honeypot.key"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    echo "TLS enabled — serving HTTPS"
    exec python -u -m uvicorn service.server:app \
        --host 0.0.0.0 --port 8080 --no-access-log \
        --ssl-certfile "$CERT" --ssl-keyfile "$KEY"
else
    echo "No TLS certs — serving plain HTTP"
    exec python -u -m uvicorn service.server:app \
        --host 0.0.0.0 --port 8080 --no-access-log
fi
