#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# HoneyForge Sensor Provisioning
#
# Run this on a fresh Ubuntu 22.04 VPS to turn it into a honeypot sensor.
# No central server needed yet — runs standalone, logs locally.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/<your-org>/honeypot/main/deploy/sensor/provision.sh | bash
#
# Or from a local clone:
#   sudo bash deploy/sensor/provision.sh
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🍯 HoneyForge Sensor Provisioning                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Check OS ──────────────────────────────────────────────────────
if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
    echo "⚠️  This script is designed for Ubuntu 22.04+. You're running:"
    cat /etc/os-release | head -1
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
fi

# ── Ensure root ───────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Re-running with sudo..."
    exec sudo bash "$0" "$@"
fi

# ── Detect public IP ──────────────────────────────────────────────
PUBLIC_IP=$(curl -s https://api.ipify.org || curl -s ifconfig.me || echo "unknown")
SENSOR_ID="hp-$(hostname)-$(date +%s | tail -c 5)"

echo "  Public IP:   $PUBLIC_IP"
echo "  Sensor ID:   $SENSOR_ID"
echo ""
read -p "  Press Enter to continue, Ctrl+C to abort: "

# ── Install dependencies ──────────────────────────────────────────
echo ""
echo "[1/7] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq \
    docker.io docker-compose-v2 \
    git curl ufw fail2ban \
    unattended-upgrades

systemctl enable docker
systemctl start docker

# ── Harden SSH (move operator SSH to port 2200) ──────────────────
echo "[2/7] Hardening operator SSH (moving to port 2200)..."
if ! grep -q "^Port 2200" /etc/ssh/sshd_config; then
    sed -i 's/^#\?Port .*/Port 2200/' /etc/ssh/sshd_config
    # Add if not present
    grep -q "^Port 2200" /etc/ssh/sshd_config || echo "Port 2200" >> /etc/ssh/sshd_config
fi
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd
echo "  ✓ Operator SSH now on port 2200 (honeypot will take :22)"

# ── Firewall: allow honeypot ports, block outbound ──────────────
echo "[3/7] Configuring firewall..."
ufw --force reset > /dev/null
ufw default deny incoming
ufw default allow outgoing  # Will tighten after central server is set up

# Operator SSH (restrict to your IP in production)
ufw allow 2200/tcp comment 'operator SSH'

# Honeypot ports (public-facing — this is the point)
ufw allow 22/tcp    comment 'SSH honeypot'
ufw allow 80/tcp    comment 'HTTP honeypot'
ufw allow 443/tcp   comment 'HTTPS honeypot (FortiGate)'
ufw allow 8080/tcp  comment 'HTTP alt'
ufw allow 2222/tcp  comment 'SSH honeypot alt'
ufw allow 4443/tcp  comment 'PaloAlto honeypot'
ufw allow 8443/tcp  comment 'Citrix honeypot'
ufw allow 10443/tcp comment 'FortiGate honeypot'

ufw --force enable
echo "  ✓ Firewall configured"

# ── Clone repo ────────────────────────────────────────────────────
echo "[4/7] Cloning HoneyForge..."
REPO_DIR="/opt/honeyforge"
if [ -d "$REPO_DIR" ]; then
    cd "$REPO_DIR" && git pull origin feat/honeyforge-initial
else
    git clone -b feat/honeyforge-initial https://github.com/threatintel560-beep/honeypot.git "$REPO_DIR"
    cd "$REPO_DIR"
fi

# ── Configure .env ────────────────────────────────────────────────
echo "[5/7] Configuring environment..."
if [ ! -f .env ]; then
    cp .env.example .env
fi
# Set unique deployment ID
sed -i "s|^HONEY_DEPLOYMENT_ID=.*|HONEY_DEPLOYMENT_ID=$SENSOR_ID|" .env
sed -i "s|^HONEY_EXTERNAL_IP=.*|HONEY_EXTERNAL_IP=$PUBLIC_IP|" .env

# Map honeypots to standard ports
sed -i "s|^SSH_PORT=.*|SSH_PORT=22|" .env
sed -i "s|^HTTP_PORT=.*|HTTP_PORT=80|" .env

# Generate SSH host key
./scripts/gen_hostkey.sh 2>/dev/null || true

# ── Start honeypots ───────────────────────────────────────────────
echo "[6/7] Starting honeypot services..."
# For sensor mode, only start honeypots (no ELK, no Intel)
docker compose up -d --build ssh-honeypot http-honeypot

# Start product-specific honeypots
docker compose --profile products up -d --build

# ── Verify ────────────────────────────────────────────────────────
echo "[7/7] Verifying services..."
sleep 5

check() {
    local name=$1 port=$2
    if timeout 2 bash -c "</dev/tcp/localhost/$port" 2>/dev/null; then
        echo "  ✓ $name on :$port"
    else
        echo "  ✗ $name on :$port (not responding)"
    fi
}

check "SSH honeypot"   22
check "HTTP honeypot"  80
check "FortiGate spoof" 10443
check "PaloAlto spoof"  4443
check "Citrix spoof"    8443

# ── Auto-updates ──────────────────────────────────────────────────
echo ""
echo "Enabling automatic security updates..."
dpkg-reconfigure -plow unattended-upgrades > /dev/null 2>&1 || true

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✓ Sensor deployed successfully                              ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                              ║"
echo "║  Sensor ID:  $SENSOR_ID"
echo "║  Public IP:  $PUBLIC_IP"
echo "║                                                              ║"
echo "║  Public-facing honeypots:                                    ║"
echo "║    ssh://$PUBLIC_IP:22                                       "
echo "║    http://$PUBLIC_IP/                                        "
echo "║    https://$PUBLIC_IP:10443 (FortiGate)                     "
echo "║    https://$PUBLIC_IP:4443  (PaloAlto)                      "
echo "║    https://$PUBLIC_IP:8443  (Citrix)                        "
echo "║                                                              ║"
echo "║  Operator SSH (YOU): ssh -p 2200 <user>@$PUBLIC_IP          "
echo "║                                                              ║"
echo "║  Logs: tail -f /opt/honeyforge/logs/http/http.json          ║"
echo "║                                                              ║"
echo "║  Test it:                                                    ║"
echo "║    curl https://$PUBLIC_IP:10443/ -k                        "
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  📡 Waiting for Censys/Shodan to find you..."
echo "  Typically takes 5-60 minutes for initial scan."
echo ""
