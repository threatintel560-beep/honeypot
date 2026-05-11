"""
CVE-2026-20128 — Catalyst SD-WAN Manager

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco Catalyst SD-WAN Manager contains a storing passwords in a recoverable format vulnerability that allows an authenticated, local attacker to gain DCA user privileges by accessing a credential file for the DCA user on the filesystem as a low-privileged user.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class CatalystSdWanManagerCve20128(CVEPlugin):
    cve_id = "CVE-2026-20128"
    product = "Catalyst SD-WAN Manager"
    severity = "critical"
    description = 'Cisco Catalyst SD-WAN Manager contains a storing passwords in a recoverable format vulnerability that allows an authenticated, local attacker to gain DCA user privileges by accessing a credential file'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2026-20128
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "catalyst_sd_wan_manager"
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
