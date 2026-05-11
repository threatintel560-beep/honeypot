"""
CVE-2018-0167 — IOS, XR, and XE Software

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: There is a buffer overflow vulnerability in the Link Layer Discovery Protocol (LLDP) subsystem of Cisco IOS Software, Cisco IOS XE Software, and Cisco IOS XR Software which could allow an unauthenticated, adjacent attacker to cause a denial of service (DoS) condition or execute arbitrary code.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class IosXrAndXeSoftwareCve0167(CVEPlugin):
    cve_id = "CVE-2018-0167"
    product = "IOS, XR, and XE Software"
    severity = "critical"
    description = 'There is a buffer overflow vulnerability in the Link Layer Discovery Protocol (LLDP) subsystem of Cisco IOS Software, Cisco IOS XE Software, and Cisco IOS XR Software which could allow an unauthentica'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2018-0167
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "ios_xr_and_xe_software"
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
