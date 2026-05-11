"""
CVE-2018-0155 — Catalyst 4500 Series Switches and Cisco Catalyst 4500-X Series Switches

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: A vulnerability in the Bidirectional Forwarding Detection (BFD) offload implementation of Cisco Catalyst 4500 Series Switches and Cisco Catalyst 4500-X Series Switches could allow an unauthenticated, remote attacker to cause a crash of the iosd process, causing a denial-of-service (DoS) condition.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class Catalyst4500SeriesSwitchesAndCiscoCatalyst4500XSeriesSwitchesCve0155(CVEPlugin):
    cve_id = "CVE-2018-0155"
    product = "Catalyst 4500 Series Switches and Cisco Catalyst 4500-X Series Switches"
    severity = "critical"
    description = 'A vulnerability in the Bidirectional Forwarding Detection (BFD) offload implementation of Cisco Catalyst 4500 Series Switches and Cisco Catalyst 4500-X Series Switches could allow an unauthenticated, '

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2018-0155
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "catalyst_4500_series_switches_and_cisco_catalyst_4500_x_series_switches"
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
