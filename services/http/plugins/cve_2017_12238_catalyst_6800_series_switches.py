"""
CVE-2017-12238 — Catalyst 6800 Series Switches

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: A vulnerability in the Virtual Private LAN Service (VPLS) code of Cisco IOS for Cisco Catalyst 6800 Series Switches could allow an unauthenticated, adjacent attacker to cause a denial of service.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class Catalyst6800SeriesSwitchesCve12238(CVEPlugin):
    cve_id = "CVE-2017-12238"
    product = "Catalyst 6800 Series Switches"
    severity = "critical"
    description = 'A vulnerability in the Virtual Private LAN Service (VPLS) code of Cisco IOS for Cisco Catalyst 6800 Series Switches could allow an unauthenticated, adjacent attacker to cause a denial of service.'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2017-12238
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "catalyst_6800_series_switches"
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
