"""
CVE-2025-35939 — Craft CMS

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Craft CMS contains an external control of assumed-immutable web parameter vulnerability. This vulnerability could allow an unauthenticated client to introduce arbitrary values, such as PHP code, to a known local file location on the server. This vulnerability could be chained with CVE-2024-58136 as represented by CVE-2025-32432.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class CraftCmsCve35939(CVEPlugin):
    cve_id = "CVE-2025-35939"
    product = "Craft CMS"
    severity = "critical"
    description = 'Craft CMS contains an external control of assumed-immutable web parameter vulnerability. This vulnerability could allow an unauthenticated client to introduce arbitrary values, such as PHP code, to a '

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2025-35939
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "craft_cms"
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
