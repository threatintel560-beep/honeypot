#!/usr/bin/env python3
"""
PCAP shipper — watches for completed pcap files and uploads to central.

tcpdump with -C 10 creates files like:
  honeypot_20260515_120000.pcap      (being written)
  honeypot_20260515_120000.pcap1     (completed, 10MB)
  honeypot_20260515_120000.pcap2     (completed, 10MB)

This script watches for numbered files (completed rotations) and uploads
them to the central controller, then deletes the local copy.

Usage:
  python3 ship_pcaps.py --central-url https://xxx.ngrok-free.dev --sensor-id hp-oracle-01

Environment:
  CENTRAL_URL, SENSOR_KEY, SENSOR_ID, PCAP_DIR
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

try:
    import httpx
except ImportError:
    print("ERROR: httpx required. pip install httpx", file=sys.stderr)
    sys.exit(1)


def find_completed_pcaps(pcap_dir: Path) -> list[Path]:
    """Find rotated pcap files (numbered ones like .pcap1, .pcap2)."""
    completed = []
    for f in sorted(pcap_dir.iterdir()):
        name = f.name
        # tcpdump -C creates: base.pcap (active), base.pcap1, base.pcap2 (completed)
        if f.is_file() and '.pcap' in name and name[-1].isdigit():
            completed.append(f)
    return completed


def upload_pcap(central_url: str, sensor_key: str, sensor_id: str, pcap_path: Path) -> bool:
    """Upload a pcap file to central."""
    url = f"{central_url.rstrip('/')}/api/sensors/pcap"
    headers = {}
    if sensor_key:
        headers["X-Sensor-Key"] = sensor_key

    try:
        with open(pcap_path, "rb") as f:
            files = {"file": (pcap_path.name, f, "application/octet-stream")}
            data = {"sensor_id": sensor_id}
            r = httpx.post(url, files=files, data=data, headers=headers, timeout=120.0)
            if r.status_code == 200:
                return True
            print(f"  [!] Upload failed: {r.status_code} {r.text[:100]}", file=sys.stderr)
    except Exception as e:
        print(f"  [!] Upload error: {e}", file=sys.stderr)
    return False


def main():
    central_url = os.getenv("CENTRAL_URL", "")
    sensor_key = os.getenv("SENSOR_KEY", "")
    sensor_id = os.getenv("SENSOR_ID", "hp-sensor-01")
    pcap_dir = Path(os.getenv("PCAP_DIR", "/opt/honeyforge/deploy/sensor/pcaps"))
    interval = int(os.getenv("PCAP_CHECK_INTERVAL", "60"))

    if not central_url:
        print("ERROR: CENTRAL_URL required", file=sys.stderr)
        sys.exit(1)

    print(f"PCAP shipper: watching {pcap_dir}")
    print(f"  Sensor: {sensor_id}")
    print(f"  Central: {central_url}")
    print(f"  Check interval: {interval}s")
    print(f"  Uploads completed 10MB pcap files, then deletes local copy")
    print()

    pcap_dir.mkdir(parents=True, exist_ok=True)

    while True:
        completed = find_completed_pcaps(pcap_dir)

        for pcap in completed:
            size_mb = pcap.stat().st_size / (1024 * 1024)
            print(f"  → Uploading {pcap.name} ({size_mb:.1f} MB)...")

            if upload_pcap(central_url, sensor_key, sensor_id, pcap):
                print(f"  ✓ Uploaded and removing local: {pcap.name}")
                pcap.unlink()
            else:
                print(f"  ✗ Upload failed, keeping local: {pcap.name}")

        time.sleep(interval)


if __name__ == "__main__":
    main()
