"""
CVE-2015-0666 — Prime Data Center Network Manager (DCNM)

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Directory traversal vulnerability in the fmserver servlet in Cisco Prime Data Center Network Manager (DCNM) allows remote attackers to read arbitrary files.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class PrimeDataCenterNetworkManagerDcnmCve0666(CVEPlugin):
    cve_id = "CVE-2015-0666"
    product = "Prime Data Center Network Manager (DCNM)"
    severity = "critical"
    description = 'Directory traversal vulnerability in the fmserver servlet in Cisco Prime Data Center Network Manager (DCNM) allows remote attackers to read arbitrary files.'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2015-0666
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "prime_data_center_network_manager_dcnm"
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
