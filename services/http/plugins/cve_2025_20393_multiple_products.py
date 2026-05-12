"""
CVE-2025-20393 — Multiple Products

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco Secure Email Gateway, Secure Email, AsyncOS Software, and Web Manager appliances contains an improper input validation vulnerability that allows threat actors to execute arbitrary commands with root privileges on the underlying operating system of an affected appliance.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class MultipleProductsCve20393(CVEPlugin):
    cve_id = "CVE-2025-20393"
    product = "Multiple Products"
    severity = "critical"
    description = 'Cisco Secure Email Gateway, Secure Email, AsyncOS Software, and Web Manager appliances contains an improper input validation vulnerability that allows threat actors to execute arbitrary commands with '

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2025-20393
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "multiple_products"
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
