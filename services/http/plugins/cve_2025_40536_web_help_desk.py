"""
CVE-2025-40536 — Web Help Desk

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: SolarWinds Web Help Desk contains a security control bypass vulnerability that could allow an unauthenticated attacker to gain access to certain restricted functionality.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class WebHelpDeskCve40536(CVEPlugin):
    cve_id = "CVE-2025-40536"
    product = "Web Help Desk"
    severity = "critical"
    description = 'SolarWinds Web Help Desk contains a security control bypass vulnerability that could allow an unauthenticated attacker to gain access to certain restricted functionality.'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2025-40536
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "web_help_desk"
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
