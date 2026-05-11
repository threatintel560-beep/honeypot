"""
Auto-pipeline — the live intelligence loop.

This ties together the full lifecycle automatically:
  1. CVE watcher finds new high-severity CVEs
  2. Plugin generator creates honeypot emulators
  3. Plugins are hot-deployed to the HTTP honeypot
  4. IOC extractor processes incoming attack traffic
  5. STIX bundles are published to the TAXII endpoint

The pipeline runs as background jobs in the intel container.
Operators can also trigger individual steps from the web UI.

Auto-deploy mode (configurable):
  - "manual"   → plugins stay as drafts, operator reviews before deploy
  - "auto_kev" → auto-deploy plugins for KEV CVEs only (actively exploited)
  - "auto_all" → auto-deploy all generated plugins (aggressive)
"""
from __future__ import annotations

import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any

from . import cve_watcher, ioc_extractor, plugin_generator, storage

log = logging.getLogger("intel.pipeline")


def run_full_cycle() -> dict[str, Any]:
    """
    Execute one full intelligence cycle:
      CVE discovery → plugin generation → deploy → IOC extraction

    Returns summary of actions taken.
    """
    storage.init_db()
    cfg = storage.all_config()
    auto_mode = cfg.get("auto_deploy_mode", "manual")

    results: dict[str, Any] = {
        "ts": int(time.time()),
        "cves_found": 0,
        "plugins_generated": 0,
        "plugins_deployed": 0,
        "iocs_extracted": 0,
    }

    # ── Step 1: Discover new CVEs ──────────────────────────────────
    try:
        cve_summary = cve_watcher.run_once()
        results["cves_found"] = cve_summary.get("new_kev", 0) + cve_summary.get("new_nvd", 0)
        log.info("pipeline_cve_watch: %s", cve_summary)
    except Exception as e:
        log.error("pipeline_cve_watch_failed: %s", e)

    # ── Step 2: Generate plugins for new CVEs ──────────────────────
    if auto_mode != "manual":
        new_cves = storage.list_cves(status="new", limit=20)
        for cve in new_cves:
            # Skip if not KEV and mode is auto_kev
            if auto_mode == "auto_kev" and not cve.get("in_kev"):
                continue

            try:
                code, model = plugin_generator.generate(cve["cve_id"], service="auto")
                # Detect which service this CVE targets
                from .service_mapper import detect_service
                target_service = detect_service(cve)
                pid = plugin_generator.save_as_draft(cve["cve_id"], target_service, code, model)
                storage.update_cve_status(cve["cve_id"], "plugin_drafted")
                results["plugins_generated"] += 1
                log.info("pipeline_plugin_generated: cve=%s service=%s model=%s",
                         cve["cve_id"], target_service, model)

                # ── Step 3: Auto-deploy if configured ──────────────
                try:
                    plugin_generator.deploy_plugin(pid)
                    results["plugins_deployed"] += 1
                    log.info("pipeline_plugin_deployed: cve=%s", cve["cve_id"])
                except Exception as e:
                    log.warning("pipeline_deploy_failed: cve=%s err=%s", cve["cve_id"], e)

            except Exception as e:
                log.error("pipeline_plugin_gen_failed: cve=%s err=%s", cve["cve_id"], e)

    # ── Step 4: Extract IOCs from recent traffic ───────────────────
    try:
        ioc_summary = ioc_extractor.run_once(window_seconds=600)  # last 10 min
        results["iocs_extracted"] = ioc_summary.get("iocs_updated", 0)
        log.info("pipeline_ioc_extract: %s", ioc_summary)
    except Exception as e:
        log.error("pipeline_ioc_extract_failed: %s", e)

    log.info("pipeline_cycle_complete: %s", results)
    return results


def notify_http_reload():
    """
    Signal the HTTP honeypot to reload plugins.

    In Docker, this sends a SIGHUP to the uvicorn process in hp-http.
    Outside Docker, it's a no-op (operator runs `make reload-http`).
    """
    try:
        result = subprocess.run(
            ["docker", "kill", "--signal=HUP", "hp-http"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            log.info("http_honeypot_reload_signaled")
        else:
            log.warning("http_reload_signal_failed: %s", result.stderr.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.debug("docker_signal_unavailable: %s (expected outside Docker)", e)


def get_pipeline_status() -> dict[str, Any]:
    """Return current pipeline state for the dashboard."""
    cfg = storage.all_config()
    cves = storage.list_cves(limit=10_000)
    plugins = storage.list_plugins()
    ioc_stats = storage.ioc_stats()

    status_counts = {}
    for c in cves:
        s = c.get("status", "unknown")
        status_counts[s] = status_counts.get(s, 0) + 1

    return {
        "auto_deploy_mode": cfg.get("auto_deploy_mode", "manual"),
        "total_cves": len(cves),
        "cve_statuses": status_counts,
        "total_plugins": len(plugins),
        "plugins_deployed": len([p for p in plugins if p["status"] == "deployed"]),
        "plugins_draft": len([p for p in plugins if p["status"] == "draft"]),
        "total_iocs": sum(ioc_stats.values()),
        "ioc_breakdown": ioc_stats,
        "taxii_api_key_set": bool(cfg.get("taxii_api_key")),
        "llm_mode": cfg.get("llm_mode", "template"),
    }
