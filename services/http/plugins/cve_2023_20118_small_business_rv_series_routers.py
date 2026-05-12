"""
CVE-2023-20118 — Small Business RV Series Routers

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Multiple Cisco Small Business RV Series Routers contains a command injection vulnerability in the web-based management interface. Successful exploitation could allow an authenticated, remote attacker to gain root-level privileges and access unauthorized data.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class SmallBusinessRvSeriesRoutersCve20118(CVEPlugin):
    cve_id = "CVE-2023-20118"
    product = "Small Business RV Series Routers"
    severity = "critical"
    description = 'Multiple Cisco Small Business RV Series Routers contains a command injection vulnerability in the web-based management interface. Successful exploitation could allow an authenticated, remote attacker '

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2023-20118
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "small_business_rv_series_routers"
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
