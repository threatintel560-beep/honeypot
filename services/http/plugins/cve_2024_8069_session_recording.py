"""
CVE-2024-8069 — Session Recording

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Citrix Session Recording contains a deserialization of untrusted data vulnerability that allows limited remote code execution with privilege of a NetworkService Account access. Attacker must be an authenticated user on the same intranet as the session recording server.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class SessionRecordingCve8069(CVEPlugin):
    cve_id = "CVE-2024-8069"
    product = "Session Recording"
    severity = "critical"
    description = 'Citrix Session Recording contains a deserialization of untrusted data vulnerability that allows limited remote code execution with privilege of a NetworkService Account access. Attacker must be an aut'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2024-8069
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "session_recording"
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
