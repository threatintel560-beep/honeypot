"""
CVE watcher — polls public feeds for new CVEs worth honeypot coverage.

Sources:
  1. CISA KEV (Known Exploited Vulnerabilities) — highest priority signal.
     JSON at https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  2. NVD recent feed — last 8 days of all CVEs with CVSS.
     JSON at https://services.nvd.nist.gov/rest/json/cves/2.0

Filtering logic (configurable in web UI):
  - Must be in KEV, OR
  - CVSS ≥ configured minimum, AND
  - product matches one of the watched products (case-insensitive substring)
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Iterable

import httpx

from . import storage

log = logging.getLogger("intel.cve_watcher")

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ── Feed fetchers ────────────────────────────────────────────────────
def _fetch_kev() -> list[dict]:
    log.info("fetching CISA KEV")
    r = httpx.get(KEV_URL, timeout=60.0,
                  headers={"User-Agent": "honeyforge-intel/0.1"})
    r.raise_for_status()
    return r.json().get("vulnerabilities", [])


def _fetch_nvd_recent(days: int = 8) -> list[dict]:
    log.info("fetching NVD (last %d days)", days)
    end   = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate":   end.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": 2000,
    }
    r = httpx.get(NVD_URL, params=params, timeout=60.0,
                  headers={"User-Agent": "honeyforge-intel/0.1"})
    r.raise_for_status()
    return r.json().get("vulnerabilities", [])


# ── Normalization ───────────────────────────────────────────────────
def _normalize_kev(kev: dict) -> dict:
    """KEV JSON shape → our internal CVE record."""
    return {
        "cve_id":      kev["cveID"],
        "vendor":      kev.get("vendorProject", ""),
        "product":     kev.get("product", ""),
        "description": kev.get("shortDescription", ""),
        "severity":    "critical",  # KEV = exploited in the wild
        "cvss":        None,
        "in_kev":      True,
        "kev_date":    kev.get("dateAdded"),
        "nvd_published": None,
        "refs":        [kev.get("notes", "")] if kev.get("notes") else [],
    }


def _normalize_nvd(nvd: dict) -> dict | None:
    cve = nvd.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None
    # Pull first English description
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    # Pull highest CVSS v3.x score
    cvss = None
    severity = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            if score is not None:
                cvss = float(score)
                severity = (data.get("baseSeverity")
                            or _sev_from_score(cvss)).lower()
                break
        if cvss:
            break

    # Pull vendor/product from first configuration
    vendor = product = ""
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                uri = cpe.get("criteria", "")
                # cpe:2.3:a:vendor:product:version:...
                parts = uri.split(":")
                if len(parts) >= 5:
                    vendor  = vendor or parts[3]
                    product = product or parts[4]
                if vendor and product:
                    break
            if vendor and product:
                break
        if vendor and product:
            break

    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")][:10]

    return {
        "cve_id":      cve_id,
        "vendor":      vendor,
        "product":     product,
        "description": desc,
        "severity":    severity,
        "cvss":        cvss,
        "in_kev":      False,
        "kev_date":    None,
        "nvd_published": cve.get("published"),
        "refs":        refs,
    }


def _sev_from_score(s: float) -> str:
    if s >= 9.0: return "critical"
    if s >= 7.0: return "high"
    if s >= 4.0: return "medium"
    return "low"


# ── Filtering ───────────────────────────────────────────────────────
def _match_watched(cve: dict, watched_products: list[str]) -> bool:
    if not watched_products:
        return True
    blob = f"{cve.get('vendor','')} {cve.get('product','')} {cve.get('description','')}".lower()
    return any(p.lower() in blob for p in watched_products)


def _passes_filter(cve: dict, cfg: dict) -> bool:
    watched  = json.loads(cfg.get("cve_watch_products") or "[]")
    min_cvss = float(cfg.get("cve_min_cvss") or 0)
    only_kev = cfg.get("cve_only_kev", "false").lower() == "true"

    if cve.get("in_kev"):
        return _match_watched(cve, watched)
    if only_kev:
        return False
    if cve.get("cvss") is None or cve["cvss"] < min_cvss:
        return False
    return _match_watched(cve, watched)


# ── Orchestration ───────────────────────────────────────────────────
def run_once() -> dict[str, int]:
    """Fetch all sources and persist. Return summary counts."""
    cfg = storage.all_config()
    new_kev = new_nvd = 0

    # KEV — every record is automatically kept
    try:
        for k in _fetch_kev():
            rec = _normalize_kev(k)
            if not _match_watched(rec, json.loads(cfg.get("cve_watch_products") or "[]")):
                continue
            if storage.upsert_cve(rec):
                new_kev += 1
    except Exception as e:
        log.error("kev_fetch_failed: %s", e)

    # NVD
    try:
        for n in _fetch_nvd_recent(days=8):
            rec = _normalize_nvd(n)
            if not rec or not _passes_filter(rec, cfg):
                continue
            if storage.upsert_cve(rec):
                new_nvd += 1
    except Exception as e:
        log.error("nvd_fetch_failed: %s", e)

    summary = {"new_kev": new_kev, "new_nvd": new_nvd, "ts": int(time.time())}
    log.info("cve_watch_complete: %s", summary)
    return summary


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    storage.init_db()
    print(json.dumps(run_once(), indent=2))
