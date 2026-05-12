"""
CVE-2024-29824 — Endpoint Manager (EPM)

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Ivanti Endpoint Manager (EPM) contains a SQL injection vulnerability in Core server that allows an unauthenticated attacker within the same network to execute arbitrary code. 
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class EndpointManagerEpmCve29824(CVEPlugin):
    cve_id = "CVE-2024-29824"
    product = "Endpoint Manager (EPM)"
    severity = "critical"
    description = 'Ivanti Endpoint Manager (EPM) contains a SQL injection vulnerability in Core server that allows an unauthenticated attacker within the same network to execute arbitrary code. '

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2024-29824
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "endpoint_manager_epm"
        return product_slug in path or product_slug in str(headers.get("user-agent","")).lower()

    def handle(self, ctx: PluginContext):
        body = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        urls = URL_RE.findall(body)

        self.log_attempt(
            ctx,
            path=ctx.request.get("path"),
            query=ctx.request.get("query"),
            dropper_urls=urls,
            payload=body[:2048],
        )

        return HTMLResponse(content="<html><body>OK</body></html>", status_code=200)
