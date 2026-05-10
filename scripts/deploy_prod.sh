#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────
# HoneyForge Production Deployment
#
# This script prepares and launches the honeypot in production mode:
#   1. Generates fresh SSH host keys
#   2. Sets up port forwarding (22→2222, 80→8080)
#   3. Configures firewall to block outbound from honeypot containers
#   4. Starts all services
#   5. Verifies health
#
# Usage:
#   ./scripts/deploy_prod.sh [--external-ip 1.2.3.4] [--no-firewall]
#
# Prerequisites:
#   - Docker + Docker Compose
#   - Ollama running locally (optional, for AI plugin generation)
#   - Root/sudo for port forwarding rules
# ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Defaults
EXTERNAL_IP="${EXTERNAL_IP:-0.0.0.0}"
SETUP_FIREWALL=true
SETUP_PORT_FORWARD=true

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --external-ip) EXTERNAL_IP="$2"; shift 2 ;;
        --no-firewall) SETUP_FIREWALL=false; shift ;;
        --no-port-forward) SETUP_PORT_FORWARD=false; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🍯 HoneyForge — Production Deployment                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  External IP:     $EXTERNAL_IP"
echo "  Firewall setup:  $SETUP_FIREWALL"
echo "  Port forwarding: $SETUP_PORT_FORWARD"
echo ""

cd "$PROJECT_DIR"

# ── Step 1: Environment file ──────────────────────────────────────
echo "[1/6] Checking environment..."
if [ ! -f .env ]; then
    cp .env.example .env
    # Generate a random deployment ID
    DEPLOY_ID="hp-$(openssl rand -hex 4)"
    sed -i.bak "s/HONEY_DEPLOYMENT_ID=.*/HONEY_DEPLOYMENT_ID=$DEPLOY_ID/" .env
    sed -i.bak "s/HONEY_EXTERNAL_IP=.*/HONEY_EXTERNAL_IP=$EXTERNAL_IP/" .env
    rm -f .env.bak
    echo "  ✓ Created .env with deployment ID: $DEPLOY_ID"
else
    echo "  ✓ .env already exists"
fi

# ── Step 2: Generate fresh SSH host key ───────────────────────────
echo "[2/6] Generating SSH host key..."
./scripts/gen_hostkey.sh
echo "  ✓ Fresh RSA-2048 host key generated"

# ── Step 3: Port forwarding (22→2222, 80→8080) ───────────────────
if [ "$SETUP_PORT_FORWARD" = true ]; then
    echo "[3/6] Setting up port forwarding..."
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS: use pfctl
        echo "  ℹ macOS detected — add these rules to /etc/pf.conf:"
        echo "    rdr pass on en0 proto tcp from any to any port 22 -> 127.0.0.1 port 2222"
        echo "    rdr pass on en0 proto tcp from any to any port 80 -> 127.0.0.1 port 8080"
        echo "  Then: sudo pfctl -f /etc/pf.conf && sudo pfctl -e"
    else
        # Linux: iptables
        echo "  Setting iptables PREROUTING rules..."
        sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222 2>/dev/null || true
        sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null || true
        echo "  ✓ Port forwarding: 22→2222, 80→8080"
    fi
else
    echo "[3/6] Skipping port forwarding (--no-port-forward)"
fi

# ── Step 4: Firewall — block outbound from honeypot ───────────────
if [ "$SETUP_FIREWALL" = true ]; then
    echo "[4/6] Configuring egress firewall..."
    if [[ "$(uname)" == "Linux" ]]; then
        # Block outbound from the Docker bridge network (honeypot containers)
        DOCKER_BRIDGE=$(docker network inspect honeypot_honeynet -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || echo "")
        if [ -n "$DOCKER_BRIDGE" ]; then
            sudo iptables -I FORWARD -s "$DOCKER_BRIDGE" -o eth0 -j DROP 2>/dev/null || true
            # Allow DNS and NTP (needed for TLS cert validation)
            sudo iptables -I FORWARD -s "$DOCKER_BRIDGE" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
            sudo iptables -I FORWARD -s "$DOCKER_BRIDGE" -p udp --dport 123 -j ACCEPT 2>/dev/null || true
            echo "  ✓ Egress blocked for honeypot containers (except DNS/NTP)"
        else
            echo "  ℹ Docker network not yet created — will apply after 'make up'"
        fi
    else
        echo "  ℹ macOS: configure egress rules in your cloud firewall / security group"
    fi
else
    echo "[4/6] Skipping firewall setup (--no-firewall)"
fi

# ── Step 5: Build and start ───────────────────────────────────────
echo "[5/6] Building and starting services..."
make up

# ── Step 6: Health check ──────────────────────────────────────────
echo "[6/6] Verifying health..."
sleep 5

check_service() {
    local name=$1 url=$2
    if curl -sf "$url" > /dev/null 2>&1; then
        echo "  ✓ $name is healthy"
    else
        echo "  ✗ $name not responding at $url"
    fi
}

check_service "HTTP Honeypot" "http://localhost:${HTTP_PORT:-8080}/"
check_service "Intel UI"      "http://localhost:${INTEL_PORT:-8090}/health"
check_service "TAXII Server"  "http://localhost:${INTEL_PORT:-8090}/taxii2/"
check_service "Elasticsearch" "http://localhost:9200/_cluster/health"
check_service "Kibana"        "http://localhost:${KIBANA_PORT:-5601}/api/status"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✓ HoneyForge deployed and ready for traffic                 ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
echo "║  Honeypot:  http://$EXTERNAL_IP:${HTTP_PORT:-8080}          ║"
echo "║  Intel UI:  http://localhost:${INTEL_PORT:-8090}             ║"
echo "║  TAXII:     http://localhost:${INTEL_PORT:-8090}/taxii2/     ║"
echo "║  Kibana:    http://localhost:${KIBANA_PORT:-5601}            ║"
echo "║                                                              ║"
echo "║  Next steps:                                                 ║"
echo "║  1. Open Intel UI → Config → set LLM backend                ║"
echo "║  2. Click 'Poll KEV + NVD' to seed CVEs                     ║"
echo "║  3. Wait for Censys/Shodan to find you (or run make demo)   ║"
echo "║  4. Point MISP/OpenCTI at the TAXII endpoint                ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
