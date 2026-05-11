"""
CVE-2026-3055 — NetScaler

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Citrix NetScaler ADC (formerly Citrix ADC), NetScaler Gateway (formerly Citrix Gateway) and NetScaler ADC FIPS and NDcPP contain an out-of-bounds reads vulnerability when configured as a SAML IDP leading to memory overread.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class NetscalerCve3055(CVEPlugin):
    cve_id = "CVE-2026-3055"
    product = "NetScaler"
    severity = "critical"
    description = 'Citrix NetScaler ADC (formerly Citrix ADC), NetScaler Gateway (formerly Citrix Gateway) and NetScaler ADC FIPS and NDcPP contain an out-of-bounds reads vulnerability when configured as a SAML IDP lead'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2026-3055
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "netscaler"
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
