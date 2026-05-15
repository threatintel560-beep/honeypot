"""
CVE-2026-42897 — Microsoft

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Microsoft Exchange Server contains a cross-site scripting vulnerability during web page generation in Outlook Web Access and when certain interaction conditions are met, arbitrary JavaScript can be executed in the browser context.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class MicrosoftCve42897(CVEPlugin):
    cve_id = "CVE-2026-42897"
    product = "Microsoft"
    severity = "critical"
    description = 'Microsoft Exchange Server contains a cross-site scripting vulnerability during web page generation in Outlook Web Access and when certain interaction conditions are met, arbitrary JavaScript can be ex'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2026-42897
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "microsoft"
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
