"""
CVE-2026-1281 — Endpoint Manager Mobile (EPMM)

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Ivanti Endpoint Manager Mobile (EPMM) contains a code injection vulnerability that could allow attackers to achieve unauthenticated remote code execution.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class EndpointManagerMobileEpmmCve1281(CVEPlugin):
    cve_id = "CVE-2026-1281"
    product = "Endpoint Manager Mobile (EPMM)"
    severity = "critical"
    description = 'Ivanti Endpoint Manager Mobile (EPMM) contains a code injection vulnerability that could allow attackers to achieve unauthenticated remote code execution.'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2026-1281
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "endpoint_manager_mobile_epmm"
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
