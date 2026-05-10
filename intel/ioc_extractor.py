"""
IOC extractor.

Reads honeypot events out of Elasticsearch, extracts indicators (URLs, IPs,
domains, hashes), deduplicates them in the intel DB, and emits STIX 2.1 bundles
that can be fed to MISP / OpenCTI / any TAXII-compatible threat-intel platform.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

import httpx

from . import storage

log = logging.getLogger("intel.ioc")

# ── Extraction regexes ─────────────────────────────────────────────
URL_RE    = re.compile(r'(?:https?|ftp|tftp)://[^\s\'"<>`()]+', re.IGNORECASE)
IPV4_RE   = re.compile(r'\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
SHA1_RE   = re.compile(r'\b[a-fA-F0-9]{40}\b')
MD5_RE    = re.compile(r'\b[a-fA-F0-9]{32}\b')
DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?:com|net|org|io|xyz|ru|cn|top|info|biz|tk|ml|ga|cf|onion|pw|cc)\b',
    re.IGNORECASE,
)

_PRIVATE_IP_PREFIXES = ("10.", "127.", "169.254.", "192.168.",
                        "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.",
                        "172.24.", "172.25.", "172.26.", "172.27.",
                        "172.28.", "172.29.", "172.30.", "172.31.",
                        "0.0.0.0")


def _is_public_ip(ip: str) -> bool:
    return not any(ip.startswith(p) for p in _PRIVATE_IP_PREFIXES)


# ── Per-event extraction ───────────────────────────────────────────
def _stringify(event: dict[str, Any]) -> str:
    """Flatten the event into one big text blob so regex can hit anything."""
    blob: list[str] = []
    for k, v in event.items():
        if isinstance(v, (dict, list)):
            blob.append(json.dumps(v, default=str))
        else:
            blob.append(str(v))
    return " ".join(blob)


def extract_from_event(event: dict[str, Any]) -> dict[str, list[str]]:
    """Return { 'url': [...], 'ipv4': [...], 'sha256': [...], 'domain': [...] }."""
    text = _stringify(event)

    urls    = list({u.rstrip(".,);]\"\'") for u in URL_RE.findall(text)})
    ipv4    = list({ip for ip in IPV4_RE.findall(text) if _is_public_ip(ip)})
    # Source IP of the attacker is always an IOC
    src_ip = event.get("src_ip")
    if src_ip and _is_public_ip(src_ip) and src_ip not in ipv4:
        ipv4.append(src_ip)

    sha256  = list({h.lower() for h in SHA256_RE.findall(text)})
    # Exclude sha1/md5 that accidentally matched longer hashes
    sha1    = [h for h in {h.lower() for h in SHA1_RE.findall(text)} if h not in sha256]
    md5     = [h for h in {h.lower() for h in MD5_RE.findall(text)} if h not in sha1 + sha256]
    domains = list({d.lower() for d in DOMAIN_RE.findall(text)})

    return {"url": urls, "ipv4": ipv4, "domain": domains,
            "sha256": sha256, "sha1": sha1, "md5": md5}


def persist_iocs(extracted: dict[str, list[str]], cve_id: str | None,
                 sensor: str | None, tags: Iterable[str] = ()) -> int:
    """Upsert all extracted IOCs into the DB. Returns total IOC count persisted."""
    cves    = [cve_id] if cve_id else []
    sensors = [sensor] if sensor else []
    count = 0
    for ioc_type, values in extracted.items():
        for v in values:
            if not v:
                continue
            storage.upsert_ioc(ioc_type, v, cves=cves, sensors=sensors, tags=tags)
            count += 1
    return count


# ── Elasticsearch pull ─────────────────────────────────────────────
def _es_search(es_url: str, index: str, since: int, size: int = 1000) -> list[dict]:
    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{since}s"}}},
                    {"bool": {"should": [
                        {"term": {"event": "cve_exploit_attempt"}},
                        {"term": {"event": "ssh_dropper_url"}},
                        {"term": {"event": "ssh_command"}},
                        {"term": {"event": "http_request"}},
                    ]}},
                ],
            },
        },
    }
    try:
        r = httpx.post(f"{es_url.rstrip('/')}/{index}/_search",
                       json=body, timeout=30.0,
                       headers={"Content-Type": "application/json"})
        r.raise_for_status()
        return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]
    except httpx.HTTPError as e:
        log.warning("es_query_failed: %s", e)
        return []


def run_once(window_seconds: int = 3600) -> dict[str, int]:
    """Pull the last `window_seconds` of events and extract IOCs."""
    cfg = storage.all_config()
    events = _es_search(
        cfg.get("es_url", "http://elasticsearch:9200"),
        cfg.get("es_index", "honeypot-events-*"),
        window_seconds,
    )

    total_iocs = 0
    for ev in events:
        extracted = extract_from_event(ev)
        total_iocs += persist_iocs(
            extracted,
            cve_id=ev.get("cve"),
            sensor=ev.get("deployment"),
            tags=[ev.get("event", "")] if ev.get("event") else [],
        )

    summary = {"events_scanned": len(events), "iocs_updated": total_iocs,
               "ts": int(time.time())}
    log.info("ioc_extract_complete: %s", summary)
    return summary


# ── STIX 2.1 bundle export ─────────────────────────────────────────
_STIX_TYPE_MAP = {
    "url":    "url",
    "ipv4":   "ipv4-addr",
    "domain": "domain-name",
    "sha256": "file",
    "sha1":   "file",
    "md5":    "file",
}

_IDENTITY_ID = f"identity--{uuid.UUID('00000000-0000-0000-0000-000000000001')}"
_IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": _IDENTITY_ID,
    "created":  "2026-01-01T00:00:00.000Z",
    "modified": "2026-01-01T00:00:00.000Z",
    "name": "HoneyForge",
    "identity_class": "organization",
    "description": "Honeypot-derived threat intelligence",
}


def _indicator_pattern(ioc_type: str, value: str) -> str:
    if ioc_type == "url":
        return f"[url:value = '{value}']"
    if ioc_type == "ipv4":
        return f"[ipv4-addr:value = '{value}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{value}']"
    if ioc_type in ("sha256", "sha1", "md5"):
        return f"[file:hashes.'{ioc_type.upper()}' = '{value}']"
    return f"[{ioc_type}:value = '{value}']"


def stix_bundle(ioc_type: str | None = None, since_seconds: int = 86400) -> dict:
    """Build a STIX 2.1 bundle of IOCs seen in the last `since_seconds`."""
    since = int(time.time()) - since_seconds
    iocs = storage.list_iocs(ioc_type=ioc_type, since=since, limit=10_000)

    objects: list[dict] = [_IDENTITY]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    for ioc in iocs:
        stable = hashlib.sha1(f"{ioc['ioc_type']}|{ioc['value']}".encode()).hexdigest()
        ind_id = f"indicator--{uuid.UUID(stable[:32])}"
        first_seen = datetime.fromtimestamp(ioc["first_seen"], tz=timezone.utc)
        last_seen  = datetime.fromtimestamp(ioc["last_seen"],  tz=timezone.utc)
        labels = ["malicious-activity"]
        try:
            labels += json.loads(ioc.get("tags") or "[]")
        except Exception:
            pass
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created_by_ref": _IDENTITY_ID,
            "created":  first_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": last_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "name": f"{ioc['ioc_type']}: {ioc['value'][:60]}",
            "pattern":      _indicator_pattern(ioc["ioc_type"], ioc["value"]),
            "pattern_type": "stix",
            "valid_from":   first_seen.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "labels":       labels,
            "x_honeyforge_hit_count": ioc.get("hit_count", 1),
            "x_honeyforge_sensors":   json.loads(ioc.get("sensors") or "[]"),
            "x_honeyforge_cves":      json.loads(ioc.get("source_cves") or "[]"),
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
        "x_honeyforge_generated_at": now,
        "x_honeyforge_ioc_count":    len(iocs),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    storage.init_db()
    print(json.dumps(run_once(), indent=2))
