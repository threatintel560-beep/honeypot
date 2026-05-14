#!/usr/bin/env python3
"""
Event shipper — runs on remote sensors, ships logs to central Intel module.

Watches the honeypot JSON log files and POSTs new events to the central
server's /api/sensors/events endpoint.

Usage:
    python3 ship_events.py --central-url https://abc123.ngrok-free.app --sensor-key mysecret

Environment variables (alternative to flags):
    CENTRAL_URL=https://abc123.ngrok-free.app
    SENSOR_KEY=mysecret
    SENSOR_ID=hp-oracle-01
    LOG_DIR=/opt/honeyforge/logs

Runs as a systemd service or in a Docker container alongside the honeypots.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

try:
    import httpx
except ImportError:
    print("ERROR: httpx required. Install with: pip install httpx", file=sys.stderr)
    sys.exit(1)


def tail_json_file(path: Path, position: int = 0) -> tuple[list[dict], int]:
    """Read new JSON lines from a file starting at position."""
    events = []
    try:
        with open(path, "r") as f:
            f.seek(position)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            new_position = f.tell()
    except FileNotFoundError:
        return [], position
    return events, new_position


def ship_batch(central_url: str, sensor_key: str, events: list[dict]) -> bool:
    """Ship a batch of events to central. Returns True on success."""
    if not events:
        return True

    url = f"{central_url.rstrip('/')}/api/sensors/events"
    headers = {"X-Sensor-Key": sensor_key} if sensor_key else {}

    try:
        r = httpx.post(url, json={"events": events}, headers=headers, timeout=30.0)
        if r.status_code == 200:
            return True
        print(f"  [!] Ship failed: status={r.status_code}", file=sys.stderr)
    except Exception as e:
        print(f"  [!] Ship error: {e}", file=sys.stderr)
    return False


def register_sensor(central_url: str, sensor_key: str, sensor_id: str,
                    public_ip: str, services: list[str], plugins: list[str]) -> bool:
    """Register this sensor with central."""
    url = f"{central_url.rstrip('/')}/api/sensors/register"
    headers = {"X-Sensor-Key": sensor_key} if sensor_key else {}
    body = {
        "sensor_id": sensor_id,
        "public_ip": public_ip,
        "services": services,
        "plugins": plugins,
    }
    try:
        r = httpx.post(url, json=body, headers=headers, timeout=15.0)
        return r.status_code == 200
    except Exception as e:
        print(f"  [!] Register failed: {e}", file=sys.stderr)
        return False


def send_heartbeat(central_url: str, sensor_key: str, sensor_id: str) -> bool:
    """Send heartbeat to central."""
    url = f"{central_url.rstrip('/')}/api/sensors/heartbeat"
    headers = {"X-Sensor-Key": sensor_key} if sensor_key else {}
    try:
        r = httpx.post(url, json={"sensor_id": sensor_id}, headers=headers, timeout=10.0)
        return r.status_code == 200
    except Exception:
        return False


def detect_public_ip() -> str:
    """Get this machine's public IP."""
    try:
        import urllib.request
        return urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode().strip()
    except Exception:
        return "unknown"


def detect_services(log_dir: Path) -> list[str]:
    """Detect which honeypot services are running based on log dirs."""
    services = []
    if (log_dir / "http").exists():
        services.append("http:80")
    if (log_dir / "ssh").exists():
        services.append("ssh:22")
    return services or ["http:80"]


def main():
    parser = argparse.ArgumentParser(description="Ship honeypot events to central Intel")
    parser.add_argument("--central-url", default=os.getenv("CENTRAL_URL", ""),
                        help="Central Intel URL (e.g. https://abc123.ngrok-free.app)")
    parser.add_argument("--sensor-key", default=os.getenv("SENSOR_KEY", ""),
                        help="Shared secret for authentication")
    parser.add_argument("--sensor-id", default=os.getenv("SENSOR_ID", ""),
                        help="Unique sensor identifier")
    parser.add_argument("--log-dir", default=os.getenv("LOG_DIR", "/opt/honeyforge/logs"),
                        help="Directory containing honeypot logs")
    parser.add_argument("--interval", type=int, default=30,
                        help="Seconds between shipping batches (default: 30)")
    parser.add_argument("--batch-size", type=int, default=50,
                        help="Max events per batch (default: 50)")
    args = parser.parse_args()

    if not args.central_url:
        print("ERROR: --central-url is required (or set CENTRAL_URL env var)")
        print("  Example: --central-url https://abc123.ngrok-free.app")
        sys.exit(1)

    log_dir = Path(args.log_dir)
    sensor_id = args.sensor_id or os.getenv("HONEY_DEPLOYMENT_ID", f"hp-{os.uname().nodename}")
    public_ip = detect_public_ip()
    services = detect_services(log_dir)

    print(f"╔══════════════════════════════════════════════════════════╗")
    print(f"║  🍯 HoneyForge Event Shipper                             ║")
    print(f"╠══════════════════════════════════════════════════════════╣")
    print(f"║  Sensor ID:   {sensor_id:<40s}  ║")
    print(f"║  Public IP:   {public_ip:<40s}  ║")
    print(f"║  Central:     {args.central_url[:40]:<40s}  ║")
    print(f"║  Log dir:     {str(log_dir)[:40]:<40s}  ║")
    print(f"║  Interval:    {args.interval}s                                       ║")
    print(f"╚══════════════════════════════════════════════════════════╝")
    print()

    # Register with central
    print(f"  Registering with central...")
    if register_sensor(args.central_url, args.sensor_key, sensor_id, public_ip, services, []):
        print(f"  ✓ Registered as {sensor_id}")
    else:
        print(f"  ⚠ Registration failed (will retry)")

    # Track file positions
    positions: dict[str, int] = {}
    heartbeat_ts = 0

    print(f"  Watching {log_dir} for events...")
    print()

    while True:
        all_events: list[dict] = []

        # Scan all JSON log files
        for json_file in log_dir.rglob("*.json"):
            pos = positions.get(str(json_file), 0)
            events, new_pos = tail_json_file(json_file, pos)
            positions[str(json_file)] = new_pos
            all_events.extend(events)

        # Ship in batches
        if all_events:
            for i in range(0, len(all_events), args.batch_size):
                batch = all_events[i:i + args.batch_size]
                ok = ship_batch(args.central_url, args.sensor_key, batch)
                if ok:
                    print(f"  → Shipped {len(batch)} events")
                else:
                    print(f"  ✗ Failed to ship {len(batch)} events (will retry)")
                    # Don't advance position on failure
                    break

        # Heartbeat every 60s
        now = time.time()
        if now - heartbeat_ts > 60:
            send_heartbeat(args.central_url, args.sensor_key, sensor_id)
            heartbeat_ts = now

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
