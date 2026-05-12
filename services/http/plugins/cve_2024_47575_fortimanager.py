"""
CVE-2024-47575 — FortiManager

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Fortinet FortiManager contains a missing authentication vulnerability in the fgfmd daemon that allows a remote, unauthenticated attacker to execute arbitrary code or commands via specially crafted requests.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class FortimanagerCve47575(CVEPlugin):
    cve_id = "CVE-2024-47575"
    product = "FortiManager"
    severity = "critical"
    description = 'Fortinet FortiManager contains a missing authentication vulnerability in the fgfmd daemon that allows a remote, unauthenticated attacker to execute arbitrary code or commands via specially crafted req'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2024-47575
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "fortimanager"
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
