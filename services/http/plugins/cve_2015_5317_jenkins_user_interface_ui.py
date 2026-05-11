"""
CVE-2015-5317 — Jenkins User Interface (UI)

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Jenkins User Interface (UI) contains an information disclosure vulnerability that allows users to see the names of jobs and builds otherwise inaccessible to them on the "Fingerprints" pages.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class JenkinsUserInterfaceUiCve5317(CVEPlugin):
    cve_id = "CVE-2015-5317"
    product = "Jenkins User Interface (UI)"
    severity = "critical"
    description = 'Jenkins User Interface (UI) contains an information disclosure vulnerability that allows users to see the names of jobs and builds otherwise inaccessible to them on the "Fingerprints" pages.'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2015-5317
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "jenkins_user_interface_ui"
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
