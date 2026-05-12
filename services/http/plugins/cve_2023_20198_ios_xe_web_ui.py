"""
CVE-2023-20198 — IOS XE Web UI

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco IOS XE Web UI contains a privilege escalation vulnerability in the web user interface that could allow a remote, unauthenticated attacker to create an account with privilege level 15 access. The attacker can then use that account to gain control of the affected device.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class IosXeWebUiCve20198(CVEPlugin):
    cve_id = "CVE-2023-20198"
    product = "IOS XE Web UI"
    severity = "critical"
    description = 'Cisco IOS XE Web UI contains a privilege escalation vulnerability in the web user interface that could allow a remote, unauthenticated attacker to create an account with privilege level 15 access. The'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2023-20198
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "ios_xe_web_ui"
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
