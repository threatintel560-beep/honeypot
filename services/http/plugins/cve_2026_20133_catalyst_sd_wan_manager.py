"""
CVE-2026-20133 — Catalyst SD-WAN Manager

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco Catalyst SD-WAN Manager contains an exposure of sensitive information to an unauthorized actor vulnerability that could allow remote attackers to view sensitive information on affected systems.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class CatalystSdWanManagerCve20133(CVEPlugin):
    cve_id = "CVE-2026-20133"
    product = "Catalyst SD-WAN Manager"
    severity = "critical"
    description = 'Cisco Catalyst SD-WAN Manager contains an exposure of sensitive information to an unauthorized actor vulnerability that could allow remote attackers to view sensitive information on affected systems.'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2026-20133
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "catalyst_sd_wan_manager"
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
