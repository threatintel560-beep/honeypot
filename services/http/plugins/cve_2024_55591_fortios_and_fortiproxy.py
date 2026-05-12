"""
CVE-2024-55591 — FortiOS and FortiProxy

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Fortinet FortiOS and FortiProxy contain an authentication bypass vulnerability that may allow an unauthenticated, remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class FortiosAndFortiproxyCve55591(CVEPlugin):
    cve_id = "CVE-2024-55591"
    product = "FortiOS and FortiProxy"
    severity = "critical"
    description = 'Fortinet FortiOS and FortiProxy contain an authentication bypass vulnerability that may allow an unauthenticated, remote attacker to gain super-admin privileges via crafted requests to Node.js websock'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2024-55591
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "fortios_and_fortiproxy"
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
