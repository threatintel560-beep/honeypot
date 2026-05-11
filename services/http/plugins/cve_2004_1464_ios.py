"""
CVE-2004-1464 — IOS

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco IOS contains an unspecified vulnerability that may block further telnet, reverse telnet, Remote Shell (RSH), Secure Shell (SSH), and in some cases, Hypertext Transport Protocol (HTTP) access to the Cisco device.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class IosCve1464(CVEPlugin):
    cve_id = "CVE-2004-1464"
    product = "IOS"
    severity = "critical"
    description = 'Cisco IOS contains an unspecified vulnerability that may block further telnet, reverse telnet, Remote Shell (RSH), Secure Shell (SSH), and in some cases, Hypertext Transport Protocol (HTTP) access to '

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2004-1464
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "ios"
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
