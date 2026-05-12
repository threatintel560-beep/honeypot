"""
CVE-2023-35082 — Endpoint Manager Mobile (EPMM) and MobileIron Core

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Ivanti Endpoint Manager Mobile (EPMM) and MobileIron Core contain an authentication bypass vulnerability that allows unauthorized users to access restricted functionality or resources of the application.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class EndpointManagerMobileEpmmAndMobileironCoreCve35082(CVEPlugin):
    cve_id = "CVE-2023-35082"
    product = "Endpoint Manager Mobile (EPMM) and MobileIron Core"
    severity = "critical"
    description = 'Ivanti Endpoint Manager Mobile (EPMM) and MobileIron Core contain an authentication bypass vulnerability that allows unauthorized users to access restricted functionality or resources of the applicati'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2023-35082
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "endpoint_manager_mobile_epmm_and_mobileiron_core"
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
