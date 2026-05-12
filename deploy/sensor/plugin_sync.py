#!/usr/bin/env python3
"""
Plugin sync agent — pulls latest CVE plugins from central Intel.

Runs inside the sensor. Periodically polls central for new plugins and
writes them to the local plugins directory. The honeypot containers
auto-reload on file changes (or we trigger a docker restart).

This allows the dashboard operator to push a plugin to a specific sensor
without needing SSH access to the sensor.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import httpx


def fetch_plugins_for_sensor(central_url: str, sensor_key: str,
                             sensor_id: str) -> list[dict]:
    """Get list of plugins assigned to this sensor from central."""
    url = f"{central_url.rstrip('/')}/api/sensors/{sensor_id}/plugins"
    headers = {"X-Sensor-Key": sensor_key} if sensor_key else {}
    try:
        r = httpx.get(url, headers=headers, timeout=15.0)
        if r.status_code == 200:
            return r.json().get("plugins", [])
    except Exception as e:
        print(f"  [!] Failed to fetch plugins: {e}", file=sys.stderr)
    return []


def download_plugin(central_url: str, sensor_key: str, plugin_id: int) -> str | None:
    """Download plugin code from central."""
    url = f"{central_url.rstrip('/')}/api/plugins/{plugin_id}/code"
    headers = {"X-Sensor-Key": sensor_key} if sensor_key else {}
    try:
        r = httpx.get(url, headers=headers, timeout=30.0)
        if r.status_code == 200:
            return r.text
    except Exception as e:
        print(f"  [!] Failed to download plugin {plugin_id}: {e}", file=sys.stderr)
    return None


def sync_plugins(central_url: str, sensor_key: str, sensor_id: str,
                 plugin_dir: Path) -> tuple[int, int]:
    """Sync plugins from central. Returns (added, updated) count."""
    plugin_dir.mkdir(parents=True, exist_ok=True)
    plugins = fetch_plugins_for_sensor(central_url, sensor_key, sensor_id)

    added = 0
    updated = 0

    for plugin in plugins:
        filename = plugin.get("filename", "")
        if not filename.endswith(".py"):
            continue

        local_path = plugin_dir / filename
        remote_code = download_plugin(central_url, sensor_key, plugin["id"])
        if remote_code is None:
            continue

        if local_path.exists():
            with open(local_path) as f:
                local_code = f.read()
            if hashlib.sha256(local_code.encode()).hexdigest() == \
               hashlib.sha256(remote_code.encode()).hexdigest():
                continue  # No change
            updated += 1
        else:
            added += 1

        local_path.write_text(remote_code)
        print(f"  ✓ {'Updated' if local_path.exists() else 'Added'}: {filename}")

    return added, updated


def main():
    central_url = os.getenv("CENTRAL_URL", "")
    sensor_key = os.getenv("SENSOR_KEY", "")
    sensor_id = os.getenv("SENSOR_ID", "hp-sensor-01")
    plugin_dir = Path(os.getenv("PLUGIN_DIR", "/app/plugins"))
    interval = int(os.getenv("SYNC_INTERVAL", "300"))  # 5 min

    if not central_url:
        print("ERROR: CENTRAL_URL required")
        sys.exit(1)

    print(f"Plugin sync: {sensor_id} ← {central_url}")
    print(f"Interval: {interval}s")

    while True:
        try:
            added, updated = sync_plugins(central_url, sensor_key, sensor_id, plugin_dir)
            if added or updated:
                print(f"  Sync complete: {added} added, {updated} updated")
        except Exception as e:
            print(f"  [!] Sync error: {e}", file=sys.stderr)
        time.sleep(interval)


if __name__ == "__main__":
    main()
