"""
CVE-2022-41082 — Exchange Server

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Microsoft Exchange Server contains an unspecified vulnerability that allows for authenticated remote code execution. Dubbed "ProxyNotShell," this vulnerability is chainable with CVE-2022-41040 which allows for the remote code execution.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class ExchangeServerCve41082(CVEPlugin):
    cve_id = "CVE-2022-41082"
    product = "Exchange Server"
    severity = "critical"
    description = 'Microsoft Exchange Server contains an unspecified vulnerability that allows for authenticated remote code execution. Dubbed "ProxyNotShell," this vulnerability is chainable with CVE-2022-41040 which a'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2022-41082
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "exchange_server"
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
