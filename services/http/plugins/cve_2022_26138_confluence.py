"""
CVE-2022-26138 — Confluence

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Atlassian Questions For Confluence App has hard-coded credentials, exposing the username and password in plaintext. A remote unauthenticated attacker can use these credentials to log into Confluence and access all content accessible to users in the confluence-users group.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class ConfluenceCve26138(CVEPlugin):
    cve_id = "CVE-2022-26138"
    product = "Confluence"
    severity = "critical"
    description = 'Atlassian Questions For Confluence App has hard-coded credentials, exposing the username and password in plaintext. A remote unauthenticated attacker can use these credentials to log into Confluence a'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2022-26138
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "confluence"
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
