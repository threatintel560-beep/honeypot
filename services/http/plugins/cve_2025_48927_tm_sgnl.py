"""
CVE-2025-48927 — TM SGNL

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: TeleMessage TM SGNL contains an initialization of a resource with an insecure default vulnerability. This vulnerability relies on how the Spring Boot Actuator is configured with an exposed heap dump endpoint at a /heapdump URI.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class TmSgnlCve48927(CVEPlugin):
    cve_id = "CVE-2025-48927"
    product = "TM SGNL"
    severity = "critical"
    description = 'TeleMessage TM SGNL contains an initialization of a resource with an insecure default vulnerability. This vulnerability relies on how the Spring Boot Actuator is configured with an exposed heap dump e'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2025-48927
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "tm_sgnl"
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
