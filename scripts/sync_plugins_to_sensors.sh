#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Sync plugins from controller to remote sensors
# Run via cron every hour on your Mac.
#
# DOES NOT TOUCH SSH CONFIG. Only syncs plugin files and restarts containers.
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PLUGIN_DIR="$PROJECT_DIR/services/http/plugins"
LOG_FILE="/tmp/honeyforge-sync.log"

# ── Sensor list (add more here) ──────────────────────────────────
# Define sensors individually for clarity
sync_sensor() {
    local host="$1"
    local port="$2"
    local key="$3"
    
    echo "$(date): Syncing to $host (port $port)" >> "$LOG_FILE"
    
    # Sync plugins via tar+ssh (works without rsync on remote)
    tar -czf /tmp/hp-plugins.tar.gz -C "$PLUGIN_DIR" . 2>/dev/null
    
    scp -P "$port" -i "$key" \
        -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        /tmp/hp-plugins.tar.gz \
        "$host:/tmp/hp-plugins.tar.gz" \
        >> "$LOG_FILE" 2>&1 || {
            echo "$(date): FAILED sync to $host" >> "$LOG_FILE"
            return 1
        }
    
    # Extract on remote and restart
    ssh -p "$port" -i "$key" \
        -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "$host" \
        "sudo tar -xzf /tmp/hp-plugins.tar.gz -C /opt/honeyforge/services/http/plugins/ && rm /tmp/hp-plugins.tar.gz && cd /opt/honeyforge/deploy/sensor && sudo docker compose -f docker-compose.sensor.yml restart http-honeypot fortinet-honeypot paloalto-honeypot citrix-honeypot 2>/dev/null" \
        >> "$LOG_FILE" 2>&1 || {
            echo "$(date): FAILED restart on $host" >> "$LOG_FILE"
            return 1
        }
    
    echo "$(date): ✓ Synced to $host" >> "$LOG_FILE"
}

# ── Add your sensors here ────────────────────────────────────────
sync_sensor "ubuntu@80.225.219.166" "22" "/Users/seru/Documents/ssh /ssh-key-2026-05-15.key"
# sync_sensor "ubuntu@ANOTHER-IP" "22" "/path/to/key"

echo "$(date): Plugin sync complete" >> "$LOG_FILE"
