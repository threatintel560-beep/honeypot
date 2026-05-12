"""
CVE-2025-20281 — Identity Services Engine

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco Identity Services Engine contains an injection vulnerability in a specific API of Cisco ISE and Cisco ISE-PIC due to insufficient validation of user-supplied input allowing an attacker to exploit this vulnerability by submitting a crafted API request. Successful exploitation could allow an attacker to perform remote code execution and obtaining root privileges on an affected device.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class IdentityServicesEngineCve20281(CVEPlugin):
    cve_id = "CVE-2025-20281"
    product = "Identity Services Engine"
    severity = "critical"
    description = 'Cisco Identity Services Engine contains an injection vulnerability in a specific API of Cisco ISE and Cisco ISE-PIC due to insufficient validation of user-supplied input allowing an attacker to exploi'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2025-20281
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "identity_services_engine"
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
