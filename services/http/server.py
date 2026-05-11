"""
HTTP high-interaction honeypot.

Flow per request:
  1. Build a Session + HttpPluginContext
  2. Ask the plugin registry if any CVE plugin claims the request
  3. Otherwise serve a realistic default page (Apache / nginx look-alike)

Every request is logged as a structured event, including body (capped) and
all headers — this is where RCE payloads, JNDI URLs, SSRF callbacks live.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse

from honeycore import Deception, PluginRegistry, Session, get_logger
from honeycore.plugins import PluginContext
from service.scanner_profiles import detect_scanner, get_default_page, SCANNER_PATHS
from service.product_profiles import get_active_profile

LOG = get_logger("http")
DECEPTION = Deception.from_env()
REGISTRY = PluginRegistry(LOG)
PRODUCT = get_active_profile()  # None = generic, or a specific product spoof

if PRODUCT:
    LOG.info("product_profile_active", extra={"data": {"product": PRODUCT.name}})

PLUGIN_DIR = Path(os.getenv("HTTP_PLUGIN_DIR", "/app/plugins"))
loaded = REGISTRY.load_from_dir(PLUGIN_DIR)
LOG.info("http_plugins_loaded", extra={"data": {"count": loaded}})

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

MAX_BODY_LOG = 16 * 1024  # 16 KB — enough for any real payload, caps log size


@app.middleware("http")
async def catch_all(request: Request, call_next):
    body = await request.body()
    session = Session(
        service="http",
        src_ip=request.client.host if request.client else "0.0.0.0",
        src_port=request.client.port if request.client else 0,
        dst_port=int(os.getenv("HTTP_LISTEN_PORT", "8080")),
    )
    session.event(
        LOG, "http_request",
        method=request.method,
        path=str(request.url.path),
        query=str(request.url.query),
        headers=dict(request.headers),
        body=body[:MAX_BODY_LOG].decode("utf-8", errors="replace"),
        body_truncated=len(body) > MAX_BODY_LOG,
        body_size=len(body),
    )

    DECEPTION.jitter()

    # Detect known scanners (Censys, Shodan, etc.)
    scanner = detect_scanner(
        session.src_ip,
        dict(request.headers),
    )
    if scanner:
        session.event(
            LOG, "recon_scan",
            scanner_name=scanner.name,
            detection_source=scanner.source,
            method=request.method,
            path=str(request.url.path),
        )

    # Serve realistic responses for common scanner probe paths
    path_lower = str(request.url.path).lower()

    # Product-specific paths take priority
    if PRODUCT and request.url.path in PRODUCT.paths:
        status, ctype, content = PRODUCT.paths[request.url.path]
        from fastapi.responses import Response as RawResponse
        resp = RawResponse(content=content, status_code=status,
                           media_type=ctype)
        return _decorate(resp)

    if path_lower in SCANNER_PATHS:
        status, ctype, content = SCANNER_PATHS[path_lower]
        from fastapi.responses import Response as RawResponse
        resp = RawResponse(content=content, status_code=status,
                           media_type=ctype)
        return _decorate(resp)

    # Try CVE plugins first
    ctx = PluginContext(
        service="http",
        session=session,
        logger=LOG,
        request={
            "method": request.method,
            "path": str(request.url.path),
            "query": str(request.url.query),
            "headers": dict(request.headers),
            "body": body,
        },
    )
    plugin = REGISTRY.dispatch(ctx)
    if plugin is not None:
        try:
            resp = plugin.handle(ctx)
        except Exception as e:
            session.event(LOG, "plugin_handle_error",
                          cve=plugin.cve_id, error=str(e))
            resp = _default_page(request)
        if isinstance(resp, Response):
            return _decorate(resp)
        # allow plugins to return (status, body, headers) tuples
        if isinstance(resp, tuple) and len(resp) == 3:
            status, content, headers = resp
            return _decorate(Response(content=content, status_code=status, headers=headers))

    # Fall through to default response unless another handler matches
    response = await call_next(request)
    return _decorate(response)


def _decorate(resp: Response) -> Response:
    """Stamp deception headers on every outgoing response."""
    if PRODUCT:
        # Product-specific spoofing
        if PRODUCT.server_header:
            resp.headers["Server"] = PRODUCT.server_header
        else:
            resp.headers.pop("Server", None)
        for k, v in PRODUCT.extra_headers.items():
            resp.headers.setdefault(k, v)
        # Remove generic headers that would give us away
        resp.headers.pop("X-Powered-By", None)
    else:
        resp.headers["Server"] = DECEPTION.http_server
        resp.headers.setdefault("X-Powered-By", "PHP/8.1.2-1ubuntu2.14")
    return resp


def _default_page(_: Request) -> HTMLResponse:
    if PRODUCT:
        return HTMLResponse(
            content=PRODUCT.default_page,
            status_code=PRODUCT.status_code,
        )
    body = get_default_page(DECEPTION.http_server)
    return HTMLResponse(content=body, status_code=200)


# Fallback routes — these run if no plugin and no other route matched
@app.get("/{full_path:path}")
async def default_get(full_path: str, request: Request):
    return _default_page(request)


@app.post("/{full_path:path}")
async def default_post(full_path: str, request: Request):
    # Many scanners expect 404 on unknown POSTs; mimic Apache
    return PlainTextResponse("Not Found", status_code=404)


@app.api_route("/{full_path:path}",
               methods=["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def default_other(full_path: str, request: Request) -> Any:
    if request.method == "OPTIONS":
        return Response(status_code=200,
                        headers={"Allow": "GET, HEAD, POST, OPTIONS"})
    return PlainTextResponse("Method Not Allowed", status_code=405)
