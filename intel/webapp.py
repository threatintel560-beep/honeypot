"""
Intel web UI.

FastAPI + Jinja2 + HTMX + Tailwind (CDN). No build step, no npm.

Pages:
  /              — dashboard with counters and recent activity
  /cves          — browse CVEs (filter by status / KEV / severity)
  /cves/{id}     — single CVE detail, research notes, generate plugin
  /plugins       — draft / reviewed / deployed plugins
  /plugins/{id}  — edit code, deploy to disk
  /iocs          — browse IOCs, download STIX bundle
  /config        — edit runtime config (LLM backend, watchers, ES)

Background jobs (APScheduler):
  - CVE watcher  — every 6h
  - IOC extractor — every 10 min
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import httpx
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import (HTMLResponse, JSONResponse, PlainTextResponse,
                               RedirectResponse, Response)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import cve_watcher, ioc_extractor, llm, plugin_generator, stix_builder, storage
from .taxii_server import router as taxii_router
from .auto_pipeline import run_full_cycle, get_pipeline_status

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("intel.webapp")

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="HoneyForge Intel", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(taxii_router)

# ── startup: init DB + schedule background jobs ────────────────────
scheduler = BackgroundScheduler(timezone="UTC")


@app.on_event("startup")
def _on_startup():
    storage.init_db()
    scheduler.add_job(cve_watcher.run_once, "interval", hours=6,
                      id="cve_watch", next_run_time=_in_seconds(30))
    scheduler.add_job(ioc_extractor.run_once, "interval", minutes=10,
                      id="ioc_extract", next_run_time=_in_seconds(60))
    scheduler.add_job(run_full_cycle, "interval", hours=12,
                      id="full_pipeline", next_run_time=_in_seconds(120))
    scheduler.start()
    log.info("intel webapp ready; background jobs scheduled (including auto-pipeline)")


def _in_seconds(n: int):
    from datetime import datetime, timedelta, timezone
    return datetime.now(timezone.utc) + timedelta(seconds=n)


# ── helpers ─────────────────────────────────────────────────────────
def _ctx(request: Request, **extra) -> dict:
    return {"request": request, "active": "", **extra}


# ═══════════════════════════════════════════════════════════════════
#  Dashboard
# ═══════════════════════════════════════════════════════════════════
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    cves       = storage.list_cves(limit=10)
    kev_total  = len([c for c in storage.list_cves(limit=10_000) if c["in_kev"]])
    all_cves   = storage.list_cves(limit=10_000)
    plugins    = storage.list_plugins()
    ioc_counts = storage.ioc_stats()

    status_breakdown = {}
    for c in all_cves:
        status_breakdown[c["status"]] = status_breakdown.get(c["status"], 0) + 1

    return templates.TemplateResponse("dashboard.html", _ctx(
        request,
        active="dashboard",
        kev_total=kev_total,
        cve_total=len(all_cves),
        cve_new=status_breakdown.get("new", 0),
        cve_deployed=status_breakdown.get("deployed", 0),
        plugin_total=len(plugins),
        plugin_drafts=len([p for p in plugins if p["status"] == "draft"]),
        ioc_counts=ioc_counts,
        recent_cves=cves,
    ))


# ═══════════════════════════════════════════════════════════════════
#  CVEs
# ═══════════════════════════════════════════════════════════════════
@app.get("/cves", response_class=HTMLResponse)
def cves_page(request: Request, status: str = "", kev_only: str = ""):
    rows = storage.list_cves(status=status or None, limit=500)
    if kev_only == "1":
        rows = [r for r in rows if r["in_kev"]]
    return templates.TemplateResponse("cves.html", _ctx(
        request, active="cves", rows=rows,
        status_filter=status, kev_only=kev_only,
    ))


@app.get("/cves/{cve_id}", response_class=HTMLResponse)
def cve_detail(request: Request, cve_id: str):
    cve = storage.get_cve(cve_id)
    if not cve:
        raise HTTPException(404, "CVE not found")
    refs = json.loads(cve.get("refs_json") or "[]")
    plugins = storage.list_plugins(cve_id=cve_id)
    return templates.TemplateResponse("cve_detail.html", _ctx(
        request, active="cves", cve=cve, refs=refs, plugins=plugins,
    ))


@app.post("/cves/{cve_id}/status")
def cve_set_status(cve_id: str, status: str = Form(...)):
    storage.update_cve_status(cve_id, status)
    return RedirectResponse(f"/cves/{cve_id}", status_code=303)


@app.post("/cves/{cve_id}/generate")
def cve_generate_plugin(cve_id: str, service: str = Form("auto")):
    code, model = plugin_generator.generate(cve_id, service=service)
    # Determine actual service used (may have been auto-detected)
    from .service_mapper import detect_service
    cve = storage.get_cve(cve_id)
    actual_service = service if service != "auto" else detect_service(cve or {})
    pid = plugin_generator.save_as_draft(cve_id, actual_service, code, model)
    storage.update_cve_status(cve_id, "plugin_drafted")
    return RedirectResponse(f"/plugins/{pid}", status_code=303)


@app.post("/cves/watch-now")
def cve_watch_now():
    cve_watcher.run_once()
    return RedirectResponse("/cves", status_code=303)


@app.post("/cves/rebuild")
def cve_rebuild():
    """Clear all CVE data and re-fetch from feeds."""
    with storage.db() as c:
        c.execute("DELETE FROM cves")
        c.execute("DELETE FROM plugins")
    cve_watcher.run_once()
    return RedirectResponse("/cves", status_code=303)


# ═══════════════════════════════════════════════════════════════════
#  Plugins
# ═══════════════════════════════════════════════════════════════════
@app.get("/plugins", response_class=HTMLResponse)
def plugins_page(request: Request):
    rows = storage.list_plugins()
    return templates.TemplateResponse("plugins.html", _ctx(
        request, active="plugins", rows=rows,
    ))


@app.get("/plugins/{plugin_id}", response_class=HTMLResponse)
def plugin_detail(request: Request, plugin_id: int):
    p = storage.get_plugin(plugin_id)
    if not p:
        raise HTTPException(404)
    return templates.TemplateResponse("plugin_detail.html", _ctx(
        request, active="plugins", plugin=p,
    ))


@app.post("/plugins/{plugin_id}/save")
def plugin_save(plugin_id: int, code: str = Form(...)):
    storage.update_plugin(plugin_id, code=code)
    return RedirectResponse(f"/plugins/{plugin_id}", status_code=303)


@app.post("/plugins/{plugin_id}/review")
def plugin_review(plugin_id: int):
    storage.update_plugin(plugin_id, status="reviewed")
    return RedirectResponse(f"/plugins/{plugin_id}", status_code=303)


@app.post("/plugins/{plugin_id}/deploy")
def plugin_deploy(plugin_id: int):
    try:
        path = plugin_generator.deploy_plugin(plugin_id)
    except Exception as e:
        return PlainTextResponse(f"Deploy failed: {e}", status_code=500)
    return RedirectResponse(f"/plugins/{plugin_id}?deployed={path.name}", status_code=303)


# ═══════════════════════════════════════════════════════════════════
#  IOCs
# ═══════════════════════════════════════════════════════════════════
@app.get("/iocs", response_class=HTMLResponse)
def iocs_page(request: Request, ioc_type: str = "", hours: int = 24):
    since = None
    if hours:
        import time
        since = int(time.time()) - hours * 3600
    rows = storage.list_iocs(ioc_type=ioc_type or None, since=since, limit=500)
    stats = storage.ioc_stats()
    for r in rows:
        r["sensors_list"] = json.loads(r.get("sensors") or "[]")
        r["cves_list"]    = json.loads(r.get("source_cves") or "[]")
    return templates.TemplateResponse("iocs.html", _ctx(
        request, active="iocs", rows=rows, stats=stats,
        ioc_type=ioc_type, hours=hours,
    ))


@app.post("/iocs/extract-now")
def iocs_extract_now():
    ioc_extractor.run_once()
    return RedirectResponse("/iocs", status_code=303)


@app.get("/iocs/stix.json")
def iocs_stix(ioc_type: str = "", hours: int = 24):
    bundle = ioc_extractor.stix_bundle(ioc_type=ioc_type or None,
                                       since_seconds=hours * 3600)
    return JSONResponse(
        bundle,
        headers={"Content-Disposition": f'attachment; filename="iocs-{hours}h.stix.json"'},
    )


@app.get("/iocs/stix-full.json")
def iocs_stix_full(cve_id: str = "", hours: int = 24):
    """Full STIX bundle with vulnerability, attack-pattern, sightings, and relationships."""
    bundle = stix_builder.full_stix_bundle(
        cve_id=cve_id or None,
        since_seconds=hours * 3600,
        include_sightings=True,
        include_attack_patterns=True,
        include_infrastructure=True,
        include_plugin_notes=True,
    )
    fname = f"honeyforge-stix-full-{cve_id or 'all'}-{hours}h.json"
    return JSONResponse(
        bundle,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ═══════════════════════════════════════════════════════════════════
#  STIX Intelligence page — shows the full lifecycle
# ═══════════════════════════════════════════════════════════════════
@app.get("/stix", response_class=HTMLResponse)
def stix_page(request: Request, cve_id: str = "", hours: int = 24):
    """Page showing the full intelligence lifecycle and STIX output."""
    cves = storage.list_cves(limit=200)
    # Get CVEs that have plugins (completed lifecycle)
    cves_with_plugins = []
    for cve in cves:
        plugins = storage.list_plugins(cve_id=cve["cve_id"])
        if plugins:
            cves_with_plugins.append({**cve, "plugin_count": len(plugins)})

    # If a specific CVE is selected, build a preview
    preview = None
    if cve_id:
        bundle = stix_builder.full_stix_bundle(
            cve_id=cve_id,
            since_seconds=hours * 3600,
        )
        type_counts: dict[str, int] = {}
        for obj in bundle["objects"]:
            t = obj.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        preview = {
            "bundle_id": bundle["id"],
            "object_count": bundle["x_honeyforge_object_count"],
            "type_counts": type_counts,
            "sample_objects": bundle["objects"][:10],
            "generated_at": bundle["x_honeyforge_generated_at"],
        }

    return templates.TemplateResponse("stix.html", _ctx(
        request,
        active="stix",
        cves_with_plugins=cves_with_plugins,
        selected_cve=cve_id,
        hours=hours,
        preview=preview,
    ))


# ═══════════════════════════════════════════════════════════════════
#  Pipeline (auto CVE → plugin → deploy → IOC → STIX)
# ═══════════════════════════════════════════════════════════════════
@app.get("/pipeline/status")
def pipeline_status():
    return JSONResponse(get_pipeline_status())


@app.post("/pipeline/run-now")
def pipeline_run_now():
    result = run_full_cycle()
    return JSONResponse(result)


# ═══════════════════════════════════════════════════════════════════
#  Services — honeypot containers and deployed plugins
# ═══════════════════════════════════════════════════════════════════
@app.get("/services", response_class=HTMLResponse)
def services_page(request: Request):
    plugins = storage.list_plugins()
    deployed = [p for p in plugins if p["status"] == "deployed"]
    cfg = storage.all_config()

    # Build plugin info for the HTTP honeypot card
    http_plugins = []
    for p in deployed:
        if p.get("service", "http") == "http":
            cve = storage.get_cve(p["cve_id"]) or {}
            http_plugins.append({
                "cve_id": p["cve_id"],
                "product": cve.get("product", "Unknown"),
                "severity": cve.get("severity", "high"),
                "filename": p.get("filename", ""),
            })

    return templates.TemplateResponse("services.html", _ctx(
        request,
        active="services",
        http_plugins=http_plugins,
        http_server_header="Apache",
        ssh_banner_short="8.9p1",
        ssh_cred_count=4,
        llm_mode=cfg.get("llm_mode", "template"),
        auto_mode=cfg.get("auto_deploy_mode", "manual"),
    ))


@app.post("/services/reload-http")
def services_reload_http():
    import subprocess
    try:
        subprocess.run(["docker", "restart", "hp-http"],
                       capture_output=True, timeout=15)
    except Exception:
        pass
    return RedirectResponse("/services", status_code=303)


# ═══════════════════════════════════════════════════════════════════
#  Network — ngrok tunnels and exposure
# ═══════════════════════════════════════════════════════════════════
@app.get("/network", response_class=HTMLResponse)
def network_page(request: Request):
    return templates.TemplateResponse("network.html", _ctx(
        request, active="network",
    ))


@app.get("/network/ngrok-status")
def ngrok_status():
    """Check if ngrok is running by querying its local API."""
    try:
        r = httpx.get("http://127.0.0.1:4040/api/tunnels", timeout=3.0)
        if r.status_code == 200:
            data = r.json()
            tunnels = []
            for t in data.get("tunnels", []):
                tunnels.append({
                    "name": t.get("name", ""),
                    "public_url": t.get("public_url", ""),
                    "port": t.get("config", {}).get("addr", "").split(":")[-1],
                })
            return JSONResponse({"running": True, "tunnels": tunnels})
    except Exception:
        pass
    return JSONResponse({"running": False, "tunnels": []})


@app.post("/network/ngrok-start")
async def ngrok_start(request: Request):
    """Start an ngrok tunnel (best-effort — may need terminal)."""
    import subprocess
    try:
        body = await request.json()
        tunnel_type = body.get("type", "honeypot")
        port = "8080" if tunnel_type == "honeypot" else "8090"
        subprocess.Popen(
            ["ngrok", "http", port, "--log=stdout"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return JSONResponse({"ok": True, "port": port})
    except FileNotFoundError:
        return JSONResponse({"error": "ngrok not installed. Run: brew install ngrok"}, status_code=500)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/network/ngrok-stop")
def ngrok_stop():
    """Stop ngrok tunnels."""
    import subprocess
    try:
        subprocess.run(["pkill", "-f", "ngrok"], capture_output=True, timeout=5)
    except Exception:
        pass
    return JSONResponse({"ok": True})


# ═══════════════════════════════════════════════════════════════════
#  Config
# ═══════════════════════════════════════════════════════════════════
@app.get("/config", response_class=HTMLResponse)
def config_page(request: Request):
    cfg = storage.all_config()
    try:
        cfg_products = json.loads(cfg.get("cve_watch_products") or "[]")
    except Exception:
        cfg_products = []
    return templates.TemplateResponse("config.html", _ctx(
        request, active="config", cfg=cfg, products_list=cfg_products,
    ))


@app.post("/config")
async def config_save(request: Request):
    form = await request.form()
    for key, value in form.items():
        if key == "cve_watch_products":
            # textarea with one product per line
            products = [ln.strip() for ln in str(value).splitlines() if ln.strip()]
            storage.set_config(key, json.dumps(products))
        else:
            storage.set_config(key, str(value))
    return RedirectResponse("/config?saved=1", status_code=303)


@app.post("/config/llm-test")
def config_llm_test():
    cfg = storage.all_config()
    backend = llm.make_backend(cfg)
    ok, msg = llm.probe(backend)
    return JSONResponse({"ok": ok, "message": msg, "backend": backend.name})


# ═══════════════════════════════════════════════════════════════════
#  Health
# ═══════════════════════════════════════════════════════════════════
@app.get("/health")
def health():
    return {"ok": True, "jobs": [j.id for j in scheduler.get_jobs()]}
