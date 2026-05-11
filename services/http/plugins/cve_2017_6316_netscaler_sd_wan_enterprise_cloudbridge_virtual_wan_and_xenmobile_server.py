"""
CVE-2017-6316 — NetScaler SD-WAN Enterprise, CloudBridge Virtual WAN, and XenMobile Server

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: A vulnerability has been identified in the management interface of Citrix NetScaler SD-WAN Enterprise and Standard Edition and Citrix CloudBridge Virtual WAN Edition that could result in an unauthenticated, remote attacker being able to execute arbitrary code as a root user. This vulnerability also affects XenMobile Server.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class NetscalerSdWanEnterpriseCloudbridgeVirtualWanAndXenmobileServerCve6316(CVEPlugin):
    cve_id = "CVE-2017-6316"
    product = "NetScaler SD-WAN Enterprise, CloudBridge Virtual WAN, and XenMobile Server"
    severity = "critical"
    description = 'A vulnerability has been identified in the management interface of Citrix NetScaler SD-WAN Enterprise and Standard Edition and Citrix CloudBridge Virtual WAN Edition that could result in an unauthenti'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2017-6316
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "netscaler_sd_wan_enterprise_cloudbridge_virtual_wan_and_xenmobile_server"
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
