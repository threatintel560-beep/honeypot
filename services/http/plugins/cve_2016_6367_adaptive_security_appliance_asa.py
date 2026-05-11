"""
CVE-2016-6367 — Adaptive Security Appliance (ASA)

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: A vulnerability in the command-line interface (CLI) parser of Cisco ASA software could allow an authenticated, local attacker to create a denial-of-service (DoS) condition or potentially execute code.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class AdaptiveSecurityApplianceAsaCve6367(CVEPlugin):
    cve_id = "CVE-2016-6367"
    product = "Adaptive Security Appliance (ASA)"
    severity = "critical"
    description = 'A vulnerability in the command-line interface (CLI) parser of Cisco ASA software could allow an authenticated, local attacker to create a denial-of-service (DoS) condition or potentially execute code.'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2016-6367
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "adaptive_security_appliance_asa"
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
