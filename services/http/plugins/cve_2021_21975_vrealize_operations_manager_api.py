"""
CVE-2021-21975 — vRealize Operations Manager API

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Server Side Request Forgery (SSRF) in vRealize Operations Manager API prior to 8.4 may allow a malicious actor with network access to the vRealize Operations Manager API to perform a SSRF attack to steal administrative credentials.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class VrealizeOperationsManagerApiCve21975(CVEPlugin):
    cve_id = "CVE-2021-21975"
    product = "vRealize Operations Manager API"
    severity = "critical"
    description = 'Server Side Request Forgery (SSRF) in vRealize Operations Manager API prior to 8.4 may allow a malicious actor with network access to the vRealize Operations Manager API to perform a SSRF attack to st'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2021-21975
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "vrealize_operations_manager_api"
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
