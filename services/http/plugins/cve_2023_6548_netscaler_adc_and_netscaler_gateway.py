"""
CVE-2023-6548 — NetScaler ADC and NetScaler Gateway

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Citrix NetScaler ADC and NetScaler Gateway contain a code injection vulnerability that allows for authenticated remote code execution on the management interface with access to NSIP, CLIP, or SNIP.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class NetscalerAdcAndNetscalerGatewayCve6548(CVEPlugin):
    cve_id = "CVE-2023-6548"
    product = "NetScaler ADC and NetScaler Gateway"
    severity = "critical"
    description = 'Citrix NetScaler ADC and NetScaler Gateway contain a code injection vulnerability that allows for authenticated remote code execution on the management interface with access to NSIP, CLIP, or SNIP.'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2023-6548
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "netscaler_adc_and_netscaler_gateway"
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
