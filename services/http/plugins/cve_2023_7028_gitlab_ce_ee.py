"""
CVE-2023-7028 — GitLab CE/EE

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: GitLab Community and Enterprise Editions contain an improper access control vulnerability. This allows an attacker to trigger password reset emails to be sent to an unverified email address to ultimately facilitate an account takeover.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class GitlabCeEeCve7028(CVEPlugin):
    cve_id = "CVE-2023-7028"
    product = "GitLab CE/EE"
    severity = "critical"
    description = 'GitLab Community and Enterprise Editions contain an improper access control vulnerability. This allows an attacker to trigger password reset emails to be sent to an unverified email address to ultimat'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2023-7028
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "gitlab_ce_ee"
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
