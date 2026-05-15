"""
Sensor event receiver — accepts attack events from remote honeypot sensors.

Remote sensors ship their JSON events to this endpoint over HTTPS.
This replaces the Filebeat → Logstash → ES pipeline for simple deployments
where the central server is behind ngrok or doesn't have a static IP.

Flow:
  Sensor Filebeat/agent → POST /api/sensors/events → Intel processes them
  
Authentication: shared secret via X-Sensor-Key header.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from . import ioc_extractor, storage

log = logging.getLogger("intel.sensor_receiver")
router = APIRouter(prefix="/api/sensors")


def _push_to_es(event: dict) -> None:
    """Push event to Elasticsearch (best-effort, non-blocking)."""
    try:
        cfg = storage.all_config()
        es_url = cfg.get("es_url", "http://elasticsearch:9200")
        index = f"honeypot-events-{time.strftime('%Y.%m.%d')}"
        import httpx as _httpx
        _httpx.post(
            f"{es_url}/{index}/_doc",
            json=event,
            headers={"Content-Type": "application/json"},
            timeout=5.0,
        )
    except Exception:
        pass  # Best-effort — don't fail event ingestion if ES is down


async def _check_sensor_key(x_sensor_key: str | None = Header(None)):
    """Validate sensor authentication key."""
    cfg = storage.all_config()
    required_key = cfg.get("sensor_api_key", "")
    if required_key and x_sensor_key != required_key:
        raise HTTPException(status_code=401, detail="Invalid sensor key")


# ── Sensor registration ────────────────────────────────────────────
@router.post("/register")
async def register_sensor(request: Request, x_sensor_key: str | None = Header(None)):
    """Register a new sensor or update heartbeat."""
    await _check_sensor_key(x_sensor_key)
    body = await request.json()

    sensor_id = body.get("sensor_id", "unknown")
    public_ip = body.get("public_ip", "")
    services = body.get("services", [])  # e.g. ["http:80", "ssh:22", "fortinet:10443"]
    plugins = body.get("plugins", [])    # list of loaded plugin CVE IDs

    storage.upsert_sensor(sensor_id, public_ip, services, plugins)
    log.info("sensor_registered: %s (%s) services=%s", sensor_id, public_ip, services)

    return JSONResponse({"ok": True, "sensor_id": sensor_id})


@router.get("/list")
async def list_sensors(x_sensor_key: str | None = Header(None)):
    """List all registered sensors."""
    await _check_sensor_key(x_sensor_key)
    sensors = storage.list_sensors()
    return JSONResponse({"sensors": sensors})


# ── Event ingestion ────────────────────────────────────────────────
@router.post("/events")
async def receive_events(request: Request, x_sensor_key: str | None = Header(None)):
    """
    Receive a batch of events from a remote sensor.
    
    Body: {"events": [{...}, {...}, ...]}
    Each event is a JSON object matching the honeypot log schema.
    """
    await _check_sensor_key(x_sensor_key)
    body = await request.json()
    events = body.get("events", [])

    if not events:
        return JSONResponse({"ok": True, "processed": 0})

    processed = 0
    iocs_found = 0

    for event in events:
        # Store the event
        storage.store_event(event)
        processed += 1

        # Also push to Elasticsearch if configured
        _push_to_es(event)

        # Extract IOCs inline
        if event.get("event") in ("cve_exploit_attempt", "http_request", "ssh_command", "ssh_dropper_url"):
            extracted = ioc_extractor.extract_from_event(event)
            count = ioc_extractor.persist_iocs(
                extracted,
                cve_id=event.get("cve"),
                sensor=event.get("deployment"),
                tags=[event.get("event", "")] if event.get("event") else [],
            )
            iocs_found += count

    # Update sensor heartbeat
    sensor_id = events[0].get("deployment", "unknown") if events else "unknown"
    storage.update_sensor_heartbeat(sensor_id, len(events))

    log.info("events_received: sensor=%s count=%d iocs=%d", sensor_id, processed, iocs_found)
    return JSONResponse({
        "ok": True,
        "processed": processed,
        "iocs_extracted": iocs_found,
    })


# ── Sensor heartbeat ──────────────────────────────────────────────
@router.post("/heartbeat")
async def heartbeat(request: Request, x_sensor_key: str | None = Header(None)):
    """Lightweight heartbeat — sensor calls this every 60s."""
    await _check_sensor_key(x_sensor_key)
    body = await request.json()
    sensor_id = body.get("sensor_id", "unknown")
    storage.update_sensor_heartbeat(sensor_id, 0)
    return JSONResponse({"ok": True, "ts": int(time.time())})



# ── Plugin assignment (for sensor plugin sync) ────────────────────
@router.get("/{sensor_id}/plugins")
async def get_sensor_plugins(sensor_id: str, x_sensor_key: str | None = Header(None)):
    """Return list of plugins assigned to this sensor."""
    await _check_sensor_key(x_sensor_key)
    plugins = storage.list_sensor_plugins(sensor_id)
    return JSONResponse({"plugins": plugins})


@router.post("/{sensor_id}/assign-plugin")
async def assign_plugin_to_sensor(sensor_id: str, request: Request,
                                   x_sensor_key: str | None = Header(None)):
    """Assign a plugin to a sensor (called from dashboard)."""
    await _check_sensor_key(x_sensor_key)
    body = await request.json()
    plugin_id = body.get("plugin_id")
    if not plugin_id:
        raise HTTPException(400, "plugin_id required")
    storage.assign_plugin_to_sensor(sensor_id, int(plugin_id))
    return JSONResponse({"ok": True})


@router.post("/{sensor_id}/unassign-plugin")
async def unassign_plugin(sensor_id: str, request: Request,
                          x_sensor_key: str | None = Header(None)):
    """Remove plugin assignment from sensor."""
    await _check_sensor_key(x_sensor_key)
    body = await request.json()
    plugin_id = body.get("plugin_id")
    if not plugin_id:
        raise HTTPException(400, "plugin_id required")
    storage.unassign_plugin_from_sensor(sensor_id, int(plugin_id))
    return JSONResponse({"ok": True})
