"""
CVE-2018-13374 — FortiOS and FortiADC

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Fortinet FortiOS and FortiADC contain an improper access control vulnerability that allows attackers to obtain the LDAP server login credentials configured in FortiGate by pointing a LDAP server connectivity test request to a rogue LDAP server.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class FortiosAndFortiadcCve13374(CVEPlugin):
    cve_id = "CVE-2018-13374"
    product = "FortiOS and FortiADC"
    severity = "critical"
    description = 'Fortinet FortiOS and FortiADC contain an improper access control vulnerability that allows attackers to obtain the LDAP server login credentials configured in FortiGate by pointing a LDAP server conne'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2018-13374
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "fortios_and_fortiadc"
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
