#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────
# Expose HoneyForge via ngrok tunnels
#
# Creates public URLs for:
#   - HTTP honeypot (port 8080) → attackers/scanners hit this
#   - Intel UI + TAXII (port 8090) → you access this for management
#
# Prerequisites:
#   - ngrok installed (brew install ngrok)
#   - ngrok account configured (ngrok config add-authtoken <token>)
#   - Docker services running (make up)
#
# Usage:
#   ./scripts/expose_ngrok.sh              # expose honeypot (free plan)
#   ./scripts/expose_ngrok.sh --intel      # expose intel/TAXII instead
#   ./scripts/expose_ngrok.sh --both       # both tunnels (paid plan)
#
# Free ngrok plan: 1 tunnel at a time. Use --intel in a second terminal.
# ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

HONEYPOT_PORT="${HTTP_PORT:-8080}"
INTEL_PORT="${INTEL_PORT:-8090}"
MODE="honeypot"

while [[ $# -gt 0 ]]; do
    case $1 in
        --intel) MODE="intel"; shift ;;
        --both) MODE="both"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Check ngrok is configured
if ! ngrok config check > /dev/null 2>&1; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ⚠️  ngrok needs authentication                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  1. Sign up free at: https://dashboard.ngrok.com/signup"
    echo "  2. Copy your auth token from: https://dashboard.ngrok.com/get-started/your-authtoken"
    echo "  3. Run:"
    echo ""
    echo "     ngrok config add-authtoken YOUR_TOKEN_HERE"
    echo ""
    echo "  4. Then re-run this script."
    echo ""
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🍯 HoneyForge — ngrok Public Exposure                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

if [ "$MODE" = "honeypot" ] || [ "$MODE" = "both" ]; then
    if ! curl -sf "http://localhost:$HONEYPOT_PORT/" > /dev/null 2>&1; then
        echo "  ⚠️  HTTP honeypot not running on port $HONEYPOT_PORT"
        echo "  Run: make up"
        exit 1
    fi
fi

if [ "$MODE" = "intel" ] || [ "$MODE" = "both" ]; then
    if ! curl -sf "http://localhost:$INTEL_PORT/health" > /dev/null 2>&1; then
        echo "  ⚠️  Intel service not running on port $INTEL_PORT"
        echo "  Run: make up"
        exit 1
    fi
fi

case $MODE in
    honeypot)
        echo "  Exposing: HTTP Honeypot (port $HONEYPOT_PORT)"
        echo ""
        echo "  Scanners and attackers will hit the public ngrok URL."
        echo "  All traffic is logged and IOCs are extracted automatically."
        echo ""
        echo "  Press Ctrl+C to stop."
        echo "─────────────────────────────────────────────────────────────"
        echo ""
        ngrok http "$HONEYPOT_PORT" --log=stdout --log-format=term
        ;;
    intel)
        echo "  Exposing: Intel UI + TAXII Server (port $INTEL_PORT)"
        echo ""
        echo "  Access the Intel dashboard and TAXII endpoint via the public URL."
        echo "  TAXII consumers can poll: <ngrok-url>/taxii2/collections/"
        echo ""
        echo "  Press Ctrl+C to stop."
        echo "─────────────────────────────────────────────────────────────"
        echo ""
        ngrok http "$INTEL_PORT" --log=stdout --log-format=term
        ;;
    both)
        echo "  Exposing both tunnels (requires ngrok paid plan):"
        echo "    Honeypot: localhost:$HONEYPOT_PORT"
        echo "    Intel:    localhost:$INTEL_PORT"
        echo ""
        echo "  Press Ctrl+C to stop."
        echo "─────────────────────────────────────────────────────────────"
        echo ""
        NGROK_CONFIG="/tmp/honeyforge-ngrok.yml"
        cat > "$NGROK_CONFIG" << EOF
version: 2
tunnels:
  honeypot:
    addr: $HONEYPOT_PORT
    proto: http
    inspect: false
  intel:
    addr: $INTEL_PORT
    proto: http
    inspect: false
EOF
        ngrok start --config "$NGROK_CONFIG" --all
        ;;
esac
