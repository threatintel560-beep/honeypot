"""
CVE-2022-36804 — Bitbucket Server and Data Center

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Multiple API endpoints of Atlassian Bitbucket Server and Data Center contain a command injection vulnerability where an attacker with access to a public Bitbucket repository, or with read permissions to a private one, can execute code by sending a malicious HTTP request.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class BitbucketServerAndDataCenterCve36804(CVEPlugin):
    cve_id = "CVE-2022-36804"
    product = "Bitbucket Server and Data Center"
    severity = "critical"
    description = 'Multiple API endpoints of Atlassian Bitbucket Server and Data Center contain a command injection vulnerability where an attacker with access to a public Bitbucket repository, or with read permissions '

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2022-36804
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "bitbucket_server_and_data_center"
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
