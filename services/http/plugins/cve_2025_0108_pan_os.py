"""
CVE-2025-0108 — PAN-OS

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Palo Alto Networks PAN-OS contains an authentication bypass vulnerability in its management web interface. This vulnerability allows an unauthenticated attacker with network access to the management web interface to bypass the authentication normally required and invoke certain PHP scripts.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class PanOsCve0108(CVEPlugin):
    cve_id = "CVE-2025-0108"
    product = "PAN-OS"
    severity = "critical"
    description = 'Palo Alto Networks PAN-OS contains an authentication bypass vulnerability in its management web interface. This vulnerability allows an unauthenticated attacker with network access to the management w'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2025-0108
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "pan_os"
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
