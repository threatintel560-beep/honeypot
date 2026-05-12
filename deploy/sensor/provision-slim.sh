#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# HoneyForge SLIM Sensor Provisioning
#
# Deploys ONLY honeypot + event shipper. No ELK, no Intel, no LLM.
# Total footprint: ~300MB RAM, ~1GB disk. Works on 1GB VPS.
#
# Usage:
#   sudo CENTRAL_URL=https://xxx.ngrok-free.app \
#        SENSOR_ID=hp-oracle-01 \
#        bash provision-slim.sh
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Required env vars ────────────────────────────────────────────
CENTRAL_URL="${CENTRAL_URL:-}"
SENSOR_ID="${SENSOR_ID:-hp-$(hostname | tr -d ' ')-$(date +%s | tail -c 5)}"
SENSOR_KEY="${SENSOR_KEY:-}"

if [ -z "$CENTRAL_URL" ]; then
    echo "ERROR: CENTRAL_URL is required"
    echo "  Usage: sudo CENTRAL_URL=https://xxx.ngrok-free.app bash provision-slim.sh"
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🍯 HoneyForge SLIM Sensor Provisioning                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

PUBLIC_IP=$(curl -s https://api.ipify.org 2>/dev/null || curl -s ifconfig.me 2>/dev/null || echo "unknown")
echo "  Sensor ID:   $SENSOR_ID"
echo "  Public IP:   $PUBLIC_IP"
echo "  Central:     $CENTRAL_URL"
echo ""

# ── Ensure root ───────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    exec sudo CENTRAL_URL="$CENTRAL_URL" SENSOR_ID="$SENSOR_ID" SENSOR_KEY="$SENSOR_KEY" bash "$0" "$@"
fi

# ── Install dependencies ──────────────────────────────────────────
echo "[1/5] Installing Docker + firewall..."
apt-get update -qq
apt-get install -y -qq docker.io docker-compose-v2 ufw fail2ban curl
systemctl enable --now docker

# ── Harden SSH ────────────────────────────────────────────────────
echo "[2/5] Hardening operator SSH (moving to port 2200)..."
if ! grep -q "^Port 2200" /etc/ssh/sshd_config; then
    sed -i 's/^#\?Port .*/Port 2200/' /etc/ssh/sshd_config
    grep -q "^Port 2200" /etc/ssh/sshd_config || echo "Port 2200" >> /etc/ssh/sshd_config
fi
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

# ── Firewall ─────────────────────────────────────────────────────
echo "[3/5] Configuring firewall..."
ufw --force reset > /dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 2200/tcp comment 'operator SSH'
ufw allow 22/tcp    comment 'SSH honeypot'
ufw allow 80/tcp    comment 'HTTP honeypot'
ufw allow 443/tcp   comment 'HTTPS'
ufw allow 8080/tcp  comment 'HTTP alt'
ufw allow 2222/tcp  comment 'SSH alt'
ufw allow 4443/tcp  comment 'PaloAlto'
ufw allow 8443/tcp  comment 'Citrix'
ufw allow 10443/tcp comment 'FortiGate'
ufw --force enable

# ── Write sensor env ──────────────────────────────────────────────
echo "[4/5] Configuring sensor..."
REPO_DIR="/opt/honeyforge"
cd "$REPO_DIR" || { echo "ERROR: $REPO_DIR not found. Run rsync from central first."; exit 1; }

# Create sensor-specific .env
cat > .env.sensor <<EOF
SENSOR_ID=$SENSOR_ID
CENTRAL_URL=$CENTRAL_URL
SENSOR_KEY=$SENSOR_KEY
HONEY_DEPLOYMENT_ID=$SENSOR_ID
HONEY_EXTERNAL_IP=$PUBLIC_IP
HTTP_PORT=80
SSH_PORT=22
FORTINET_PORT=10443
PALOALTO_PORT=4443
CITRIX_PORT=8443
SSH_BANNER=auto
SSH_HOSTNAME=auto
HTTP_SERVER_HEADER=auto
DECEPTION_STRICT=true
RESPONSE_JITTER_MIN=10
RESPONSE_JITTER_MAX=120
EOF

# Link main .env to sensor .env
cp .env.sensor .env

# Generate SSH host key
bash scripts/gen_hostkey.sh 2>/dev/null || true

# ── Start slim stack ──────────────────────────────────────────────
echo "[5/5] Starting honeypot containers + shipper..."
cd "$REPO_DIR/deploy/sensor"
docker compose -f docker-compose.sensor.yml up -d --build

sleep 5

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✓ Slim sensor deployed                                      ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Sensor:       $SENSOR_ID"
echo "║  Public IP:    $PUBLIC_IP"
echo "║  Shipping to:  $CENTRAL_URL"
echo "║                                                              ║"
echo "║  Ports exposed to attackers:                                 ║"
echo "║    :22    SSH honeypot                                       ║"
echo "║    :80    HTTP honeypot                                      ║"
echo "║    :4443  PaloAlto spoof                                     ║"
echo "║    :8443  Citrix spoof                                       ║"
echo "║    :10443 FortiGate spoof                                    ║"
echo "║                                                              ║"
echo "║  Operator SSH: ssh -p 2200 ubuntu@$PUBLIC_IP                 "
echo "║                                                              ║"
echo "║  Memory used: ~300MB · Disk: ~1GB                            ║"
echo "║                                                              ║"
echo "║  View on central: $CENTRAL_URL/services"
echo "╚══════════════════════════════════════════════════════════════╝"
