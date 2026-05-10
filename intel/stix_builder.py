"""
STIX 2.1 bundle builder — full threat intelligence output.

Produces a rich STIX bundle that captures the complete honeypot intelligence
lifecycle:

  CVE researched → plugin generated → attack observed → IOCs extracted

Object types emitted:
  - identity        (HoneyForge sensor)
  - vulnerability   (the CVE itself)
  - attack-pattern  (MITRE ATT&CK mapping)
  - indicator       (IOCs: IPs, URLs, domains, hashes)
  - sighting        (observed attack against the honeypot)
  - malware         (if dropper/payload identified)
  - infrastructure  (C2 servers, dropper hosts)
  - relationship    (links between all the above)

Conforms to STIX 2.1 (OASIS standard) and is importable by:
  - MISP, OpenCTI, TheHive/Cortex, any TAXII 2.1 server
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from . import storage

# ── Constants ──────────────────────────────────────────────────────
HONEYFORGE_IDENTITY_ID = "identity--00000000-0000-0000-0000-000000000001"
HONEYFORGE_IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": HONEYFORGE_IDENTITY_ID,
    "created": "2026-01-01T00:00:00.000Z",
    "modified": "2026-01-01T00:00:00.000Z",
    "name": "HoneyForge",
    "identity_class": "system",
    "description": "Automated honeypot threat intelligence platform",
    "sectors": ["technology"],
    "contact_information": "honeyforge-intel",
}

# MITRE ATT&CK technique mappings for common CVE exploitation patterns
_ATTACK_PATTERNS = {
    "rce": {
        "name": "Exploitation for Client Execution",
        "external_id": "T1203",
        "kill_chain": "initial-access",
    },
    "command_injection": {
        "name": "Command and Scripting Interpreter",
        "external_id": "T1059",
        "kill_chain": "execution",
    },
    "path_traversal": {
        "name": "Path Interception",
        "external_id": "T1574",
        "kill_chain": "persistence",
    },
    "deserialization": {
        "name": "Exploitation of Remote Services",
        "external_id": "T1210",
        "kill_chain": "lateral-movement",
    },
    "ssrf": {
        "name": "Server Software Component",
        "external_id": "T1505",
        "kill_chain": "persistence",
    },
    "default": {
        "name": "Exploit Public-Facing Application",
        "external_id": "T1190",
        "kill_chain": "initial-access",
    },
}


def _now_stix() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _deterministic_id(prefix: str, seed: str) -> str:
    """Generate a deterministic STIX ID from a seed string."""
    h = hashlib.sha256(seed.encode()).hexdigest()[:32]
    # Format as UUID
    uid = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    return f"{prefix}--{uid}"


def _ts_to_stix(ts: int | float | None) -> str:
    if ts is None:
        return _now_stix()
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ── Object builders ────────────────────────────────────────────────
def build_vulnerability(cve: dict) -> dict:
    """Build a STIX vulnerability object from a CVE record."""
    cve_id = cve["cve_id"]
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": _deterministic_id("vulnerability", cve_id),
        "created_by_ref": HONEYFORGE_IDENTITY_ID,
        "created": _ts_to_stix(cve.get("added_at")),
        "modified": _now_stix(),
        "name": cve_id,
        "description": cve.get("description", ""),
        "external_references": [
            {
                "source_name": "cve",
                "external_id": cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        ],
        "x_honeyforge_product": cve.get("product", ""),
        "x_honeyforge_vendor": cve.get("vendor", ""),
        "x_honeyforge_cvss": cve.get("cvss"),
        "x_honeyforge_severity": cve.get("severity", ""),
        "x_honeyforge_in_kev": bool(cve.get("in_kev")),
        "x_honeyforge_status": cve.get("status", "new"),
    }


def build_attack_pattern(cve: dict) -> dict:
    """Infer ATT&CK technique from CVE description and build attack-pattern."""
    desc = (cve.get("description") or "").lower()

    # Simple keyword matching to pick the best ATT&CK technique
    technique = _ATTACK_PATTERNS["default"]
    if any(kw in desc for kw in ("remote code", "rce", "code execution")):
        technique = _ATTACK_PATTERNS["rce"]
    elif any(kw in desc for kw in ("command injection", "os command")):
        technique = _ATTACK_PATTERNS["command_injection"]
    elif any(kw in desc for kw in ("path traversal", "directory traversal")):
        technique = _ATTACK_PATTERNS["path_traversal"]
    elif any(kw in desc for kw in ("deserialization", "deserialize")):
        technique = _ATTACK_PATTERNS["deserialization"]
    elif any(kw in desc for kw in ("ssrf", "server-side request")):
        technique = _ATTACK_PATTERNS["ssrf"]

    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": _deterministic_id("attack-pattern", f"{cve['cve_id']}:{technique['external_id']}"),
        "created_by_ref": HONEYFORGE_IDENTITY_ID,
        "created": _ts_to_stix(cve.get("added_at")),
        "modified": _now_stix(),
        "name": technique["name"],
        "description": f"Exploitation technique observed via {cve['cve_id']}",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": technique["external_id"],
                "url": f"https://attack.mitre.org/techniques/{technique['external_id']}/",
            }
        ],
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": technique["kill_chain"],
            }
        ],
    }


def build_indicator(ioc: dict) -> dict:
    """Build a STIX indicator from an IOC record."""
    ioc_type = ioc["ioc_type"]
    value = ioc["value"]

    pattern_map = {
        "url": f"[url:value = '{value}']",
        "ipv4": f"[ipv4-addr:value = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "sha256": f"[file:hashes.'SHA-256' = '{value}']",
        "sha1": f"[file:hashes.'SHA-1' = '{value}']",
        "md5": f"[file:hashes.'MD5' = '{value}']",
    }

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _deterministic_id("indicator", f"{ioc_type}|{value}"),
        "created_by_ref": HONEYFORGE_IDENTITY_ID,
        "created": _ts_to_stix(ioc.get("first_seen")),
        "modified": _ts_to_stix(ioc.get("last_seen")),
        "name": f"{ioc_type}: {value[:80]}",
        "pattern": pattern_map.get(ioc_type, f"[{ioc_type}:value = '{value}']"),
        "pattern_type": "stix",
        "valid_from": _ts_to_stix(ioc.get("first_seen")),
        "indicator_types": ["malicious-activity"],
        "labels": _safe_json_list(ioc.get("tags")),
        "x_honeyforge_hit_count": ioc.get("hit_count", 1),
        "x_honeyforge_sensors": _safe_json_list(ioc.get("sensors")),
        "x_honeyforge_cves": _safe_json_list(ioc.get("source_cves")),
    }


def build_sighting(
    indicator_id: str,
    observed_data: dict[str, Any],
    cve_id: str | None = None,
) -> dict:
    """Build a STIX sighting — an observed attack against the honeypot."""
    now = _now_stix()
    sighting_id = f"sighting--{uuid.uuid4()}"

    sighting = {
        "type": "sighting",
        "spec_version": "2.1",
        "id": sighting_id,
        "created_by_ref": HONEYFORGE_IDENTITY_ID,
        "created": now,
        "modified": now,
        "first_seen": observed_data.get("first_seen", now),
        "last_seen": observed_data.get("last_seen", now),
        "count": observed_data.get("count", 1),
        "sighting_of_ref": indicator_id,
        "where_sighted_refs": [HONEYFORGE_IDENTITY_ID],
        "x_honeyforge_sensor": observed_data.get("sensor", ""),
        "x_honeyforge_service": observed_data.get("service", "http"),
    }

    if cve_id:
        sighting["x_honeyforge_cve"] = cve_id

    return sighting


def build_infrastructure(url_or_ip: str, infra_type: str = "command-and-control") -> dict:
    """Build a STIX infrastructure object for C2/dropper hosts."""
    return {
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": _deterministic_id("infrastructure", url_or_ip),
        "created_by_ref": HONEYFORGE_IDENTITY_ID,
        "created": _now_stix(),
        "modified": _now_stix(),
        "name": f"Attacker infrastructure: {url_or_ip[:60]}",
        "infrastructure_types": [infra_type],
        "x_honeyforge_value": url_or_ip,
    }


def build_relationship(
    source_id: str,
    target_id: str,
    relationship_type: str,
    description: str = "",
) -> dict:
    """Build a STIX relationship object."""
    now = _now_stix()
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{uuid.uuid4()}",
        "created_by_ref": HONEYFORGE_IDENTITY_ID,
        "created": now,
        "modified": now,
        "relationship_type": relationship_type,
        "source_ref": source_id,
        "target_ref": target_id,
        "description": description,
    }


def build_note(content: str, object_refs: list[str], abstract: str = "") -> dict:
    """Build a STIX note — used for plugin generation context."""
    now = _now_stix()
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": f"note--{uuid.uuid4()}",
        "created_by_ref": HONEYFORGE_IDENTITY_ID,
        "created": now,
        "modified": now,
        "abstract": abstract or "HoneyForge plugin generation context",
        "content": content,
        "object_refs": object_refs,
    }


# ── Full bundle assembly ───────────────────────────────────────────
def full_stix_bundle(
    cve_id: str | None = None,
    since_seconds: int = 86400,
    include_sightings: bool = True,
    include_attack_patterns: bool = True,
    include_infrastructure: bool = True,
    include_plugin_notes: bool = True,
) -> dict:
    """
    Build a comprehensive STIX 2.1 bundle showing the full intelligence
    lifecycle for a CVE (or all recent activity).

    This is the "money shot" — it shows:
      1. The CVE that was researched (vulnerability)
      2. The ATT&CK technique mapped (attack-pattern)
      3. The plugin that was generated (note)
      4. The attacks observed (sighting)
      5. The IOCs extracted (indicator)
      6. Attacker infrastructure identified (infrastructure)
      7. All relationships between these objects
    """
    objects: list[dict] = [HONEYFORGE_IDENTITY]
    relationships: list[dict] = []
    since = int(time.time()) - since_seconds

    # ── 1. CVE / Vulnerability objects ─────────────────────────────
    if cve_id:
        cves = [storage.get_cve(cve_id)] if storage.get_cve(cve_id) else []
    else:
        cves = storage.list_cves(limit=100)

    vuln_ids: dict[str, str] = {}  # cve_id → STIX vulnerability ID
    for cve in cves:
        if not cve:
            continue
        vuln = build_vulnerability(cve)
        objects.append(vuln)
        vuln_ids[cve["cve_id"]] = vuln["id"]

        # ── 2. Attack patterns ─────────────────────────────────────
        if include_attack_patterns:
            ap = build_attack_pattern(cve)
            objects.append(ap)
            relationships.append(build_relationship(
                vuln["id"], ap["id"], "uses",
                f"Exploitation of {cve['cve_id']} uses {ap['name']}",
            ))

        # ── 3. Plugin generation notes ─────────────────────────────
        if include_plugin_notes:
            plugins = storage.list_plugins(cve_id=cve["cve_id"])
            for plugin in plugins:
                note_content = (
                    f"Plugin generated for {cve['cve_id']}\n"
                    f"Service: {plugin.get('service', 'http')}\n"
                    f"Model: {plugin.get('model_used', 'unknown')}\n"
                    f"Status: {plugin.get('status', 'draft')}\n"
                    f"Filename: {plugin.get('filename', '')}\n"
                    f"Generated at: {_ts_to_stix(plugin.get('created_at'))}"
                )
                note = build_note(
                    content=note_content,
                    object_refs=[vuln["id"]],
                    abstract=f"Honeypot plugin: {plugin.get('filename', cve['cve_id'])}",
                )
                objects.append(note)

    # ── 4. IOC indicators ──────────────────────────────────────────
    iocs = storage.list_iocs(since=since, limit=10_000)
    if cve_id:
        # Filter IOCs linked to this specific CVE
        iocs = [i for i in iocs if cve_id in _safe_json_list(i.get("source_cves"))]

    indicator_ids: dict[str, str] = {}  # value → STIX indicator ID
    for ioc in iocs:
        ind = build_indicator(ioc)
        objects.append(ind)
        indicator_ids[ioc["value"]] = ind["id"]

        # Link indicator to vulnerability
        ioc_cves = _safe_json_list(ioc.get("source_cves"))
        for linked_cve in ioc_cves:
            if linked_cve in vuln_ids:
                relationships.append(build_relationship(
                    ind["id"], vuln_ids[linked_cve], "indicates",
                    f"IOC {ioc['ioc_type']}:{ioc['value'][:40]} indicates exploitation of {linked_cve}",
                ))

        # ── 5. Sightings ──────────────────────────────────────────
        if include_sightings and ioc.get("hit_count", 0) > 0:
            sighting = build_sighting(
                indicator_id=ind["id"],
                observed_data={
                    "first_seen": _ts_to_stix(ioc.get("first_seen")),
                    "last_seen": _ts_to_stix(ioc.get("last_seen")),
                    "count": ioc.get("hit_count", 1),
                    "sensor": (_safe_json_list(ioc.get("sensors")) or ["unknown"])[0],
                    "service": "http",
                },
                cve_id=ioc_cves[0] if ioc_cves else None,
            )
            objects.append(sighting)

        # ── 6. Infrastructure ──────────────────────────────────────
        if include_infrastructure and ioc["ioc_type"] == "url":
            infra = build_infrastructure(ioc["value"], "hosting-malware")
            objects.append(infra)
            relationships.append(build_relationship(
                ind["id"], infra["id"], "based-on",
                f"Indicator based on infrastructure {ioc['value'][:40]}",
            ))

    # ── 7. Add all relationships ───────────────────────────────────
    objects.extend(relationships)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
        "x_honeyforge_generated_at": _now_stix(),
        "x_honeyforge_cve_filter": cve_id,
        "x_honeyforge_object_count": len(objects),
        "x_honeyforge_time_window_seconds": since_seconds,
    }


# ── Helpers ────────────────────────────────────────────────────────
def _safe_json_list(val: Any) -> list:
    """Parse a JSON string to list, or return empty list."""
    if isinstance(val, list):
        return val
    if not val:
        return []
    try:
        result = json.loads(val)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, TypeError):
        return []
