"""
CVE-2022-20775 — SD-WAN

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco SD-WAN CLI contains a path traversal vulnerability that could allow an authenticated local attacker to gain elevated privileges via improper access controls on commands within the application CLI. A successful exploit could allow the attacker to execute arbitrary commands as the root user.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class SdWanCve20775(CVEPlugin):
    cve_id = "CVE-2022-20775"
    product = "SD-WAN"
    severity = "critical"
    description = 'Cisco SD-WAN CLI contains a path traversal vulnerability that could allow an authenticated local attacker to gain elevated privileges via improper access controls on commands within the application CL'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2022-20775
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "sd_wan"
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
