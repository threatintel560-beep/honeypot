"""
CVE-2020-3433 — AnyConnect Secure

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco AnyConnect Secure Mobility Client for Windows interprocess communication (IPC) channel allows for insufficient validation of resources that are loaded by the application at run time. An attacker with valid credentials on Windows could execute code on the affected machine with SYSTEM privileges.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class AnyconnectSecureCve3433(CVEPlugin):
    cve_id = "CVE-2020-3433"
    product = "AnyConnect Secure"
    severity = "critical"
    description = 'Cisco AnyConnect Secure Mobility Client for Windows interprocess communication (IPC) channel allows for insufficient validation of resources that are loaded by the application at run time. An attacker'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2020-3433
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "anyconnect_secure"
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
