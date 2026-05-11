"""
CVE-2018-0161 — IOS Software

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: A vulnerability in the Simple Network Management Protocol (SNMP) subsystem of Cisco IOS Software running on certain models of Cisco Catalyst Switches could allow an authenticated, remote attacker to cause a denial-of-service (DoS) condition.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class IosSoftwareCve0161(CVEPlugin):
    cve_id = "CVE-2018-0161"
    product = "IOS Software"
    severity = "critical"
    description = 'A vulnerability in the Simple Network Management Protocol (SNMP) subsystem of Cisco IOS Software running on certain models of Cisco Catalyst Switches could allow an authenticated, remote attacker to c'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2018-0161
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "ios_software"
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
