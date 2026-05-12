"""
CVE-2021-39935 — Community and Enterprise Editions

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: GitLab Community and Enterprise Editions contain a server-side request forgery vulnerability which could allow unauthorized external users to perform Server Side Requests via the CI Lint API. 
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class CommunityAndEnterpriseEditionsCve39935(CVEPlugin):
    cve_id = "CVE-2021-39935"
    product = "Community and Enterprise Editions"
    severity = "critical"
    description = 'GitLab Community and Enterprise Editions contain a server-side request forgery vulnerability which could allow unauthorized external users to perform Server Side Requests via the CI Lint API. '

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2021-39935
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "community_and_enterprise_editions"
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
