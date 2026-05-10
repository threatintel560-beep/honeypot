"""
TAXII 2.1 server — serves STIX bundles to threat intel consumers.

Implements the TAXII 2.1 spec (OASIS) endpoints:
  GET  /taxii2/              → discovery (server info)
  GET  /taxii2/collections/  → list collections
  GET  /taxii2/collections/{id}/  → collection detail
  GET  /taxii2/collections/{id}/objects/  → get STIX objects
  POST /taxii2/collections/{id}/objects/  → add STIX objects (internal)
  GET  /taxii2/collections/{id}/manifest/ → object manifest

This runs as part of the intel webapp (mounted as a sub-app).
Consumers (MISP, OpenCTI, TheHive) poll this endpoint on a schedule.

Authentication: API key via X-TAXII-Key header (configurable).
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from . import stix_builder, storage

router = APIRouter(prefix="/taxii2")

TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"
STIX_CONTENT_TYPE = "application/stix+json;version=2.1"

# Collection IDs (stable)
COLLECTION_ALL = "honeyforge-all-intel"
COLLECTION_IOCS = "honeyforge-iocs"
COLLECTION_CVES = "honeyforge-cve-intel"

COLLECTIONS = [
    {
        "id": COLLECTION_ALL,
        "title": "HoneyForge — All Intelligence",
        "description": "Complete STIX bundles: vulnerabilities, attack patterns, indicators, sightings, infrastructure",
        "can_read": True,
        "can_write": False,
        "media_types": [STIX_CONTENT_TYPE],
    },
    {
        "id": COLLECTION_IOCS,
        "title": "HoneyForge — IOCs Only",
        "description": "Indicators of compromise extracted from honeypot traffic (IPs, URLs, domains, hashes)",
        "can_read": True,
        "can_write": False,
        "media_types": [STIX_CONTENT_TYPE],
    },
    {
        "id": COLLECTION_CVES,
        "title": "HoneyForge — CVE Intelligence",
        "description": "Vulnerability objects with attack patterns and plugin generation context",
        "can_read": True,
        "can_write": False,
        "media_types": [STIX_CONTENT_TYPE],
    },
]


def _taxii_response(data: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(
        content=data,
        status_code=status,
        media_type=TAXII_CONTENT_TYPE,
    )


def _stix_response(data: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(
        content=data,
        status_code=status,
        media_type=STIX_CONTENT_TYPE,
    )


async def _check_api_key(x_taxii_key: str | None = Header(None)):
    """Validate TAXII API key if one is configured."""
    cfg = storage.all_config()
    required_key = cfg.get("taxii_api_key", "")
    if required_key and x_taxii_key != required_key:
        raise HTTPException(
            status_code=401,
            detail={"title": "Unauthorized", "description": "Invalid or missing X-TAXII-Key header"},
        )


# ── Discovery ──────────────────────────────────────────────────────
@router.get("/")
async def discovery(_=Depends(_check_api_key)):
    """TAXII 2.1 discovery endpoint."""
    return _taxii_response({
        "title": "HoneyForge TAXII Server",
        "description": "Honeypot-derived threat intelligence — auto-generated from live attack traffic",
        "contact": "honeyforge-intel",
        "default": f"/taxii2/collections/{COLLECTION_ALL}/",
        "api_roots": ["/taxii2/"],
    })


# ── Collections ────────────────────────────────────────────────────
@router.get("/collections/")
async def list_collections(_=Depends(_check_api_key)):
    return _taxii_response({"collections": COLLECTIONS})


@router.get("/collections/{collection_id}/")
async def get_collection(collection_id: str, _=Depends(_check_api_key)):
    for c in COLLECTIONS:
        if c["id"] == collection_id:
            return _taxii_response(c)
    raise HTTPException(404, {"title": "Not Found", "description": f"Collection {collection_id} not found"})


# ── Objects ────────────────────────────────────────────────────────
@router.get("/collections/{collection_id}/objects/")
async def get_objects(
    collection_id: str,
    added_after: str | None = None,
    type: str | None = None,
    limit: int = 100,
    _=Depends(_check_api_key),
):
    """Return STIX objects from the collection."""
    # Determine time window
    since_seconds = 86400 * 30  # default: last 30 days
    if added_after:
        try:
            dt = datetime.fromisoformat(added_after.replace("Z", "+00:00"))
            since_seconds = int((datetime.now(timezone.utc) - dt).total_seconds())
        except (ValueError, TypeError):
            pass

    # Build the appropriate bundle
    if collection_id == COLLECTION_ALL:
        bundle = stix_builder.full_stix_bundle(
            since_seconds=since_seconds,
            include_sightings=True,
            include_attack_patterns=True,
            include_infrastructure=True,
            include_plugin_notes=True,
        )
    elif collection_id == COLLECTION_IOCS:
        from . import ioc_extractor
        bundle = ioc_extractor.stix_bundle(since_seconds=since_seconds)
    elif collection_id == COLLECTION_CVES:
        bundle = stix_builder.full_stix_bundle(
            since_seconds=since_seconds,
            include_sightings=False,
            include_attack_patterns=True,
            include_infrastructure=False,
            include_plugin_notes=True,
        )
    else:
        raise HTTPException(404, {"title": "Not Found"})

    # Filter by type if requested
    objects = bundle.get("objects", [])
    if type:
        objects = [o for o in objects if o.get("type") == type]

    # Apply limit
    objects = objects[:limit]

    # TAXII envelope
    envelope = {
        "more": len(bundle.get("objects", [])) > limit,
        "objects": objects,
    }

    return _stix_response(envelope)


# ── Manifest ───────────────────────────────────────────────────────
@router.get("/collections/{collection_id}/manifest/")
async def get_manifest(
    collection_id: str,
    added_after: str | None = None,
    limit: int = 100,
    _=Depends(_check_api_key),
):
    """Return manifest of available objects (lightweight metadata)."""
    since_seconds = 86400 * 30
    if added_after:
        try:
            dt = datetime.fromisoformat(added_after.replace("Z", "+00:00"))
            since_seconds = int((datetime.now(timezone.utc) - dt).total_seconds())
        except (ValueError, TypeError):
            pass

    bundle = stix_builder.full_stix_bundle(since_seconds=since_seconds)
    objects = bundle.get("objects", [])[:limit]

    manifest_entries = []
    for obj in objects:
        manifest_entries.append({
            "id": obj.get("id", ""),
            "date_added": obj.get("created", ""),
            "version": obj.get("modified", obj.get("created", "")),
            "media_type": STIX_CONTENT_TYPE,
        })

    return _taxii_response({
        "more": len(bundle.get("objects", [])) > limit,
        "objects": manifest_entries,
    })
