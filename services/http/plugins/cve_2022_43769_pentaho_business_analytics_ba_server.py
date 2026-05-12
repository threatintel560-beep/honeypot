"""
CVE-2022-43769 — Pentaho Business Analytics (BA) Server

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Hitachi Vantara Pentaho BA Server contains a special element injection vulnerability that allows an attacker to inject Spring templates into properties files, allowing for arbitrary command execution.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class PentahoBusinessAnalyticsBaServerCve43769(CVEPlugin):
    cve_id = "CVE-2022-43769"
    product = "Pentaho Business Analytics (BA) Server"
    severity = "critical"
    description = 'Hitachi Vantara Pentaho BA Server contains a special element injection vulnerability that allows an attacker to inject Spring templates into properties files, allowing for arbitrary command execution.'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2022-43769
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "pentaho_business_analytics_ba_server"
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
