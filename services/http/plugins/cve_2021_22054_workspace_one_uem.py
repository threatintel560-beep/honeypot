"""
CVE-2021-22054 — Workspace One UEM

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Omnissa Workspace One UEM formerly known as VMware Workspace One UEM contains a server-side request forgery (SSRF) vulnerability that could allow a malicious actor with network access to UEM to send their requests without authentication and to gain access to sensitive information.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class WorkspaceOneUemCve22054(CVEPlugin):
    cve_id = "CVE-2021-22054"
    product = "Workspace One UEM"
    severity = "critical"
    description = 'Omnissa Workspace One UEM formerly known as VMware Workspace One UEM contains a server-side request forgery (SSRF) vulnerability that could allow a malicious actor with network access to UEM to send t'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2021-22054
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "workspace_one_uem"
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
