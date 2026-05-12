"""
CVE-2023-38035 — Sentry

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Ivanti Sentry, formerly known as MobileIron Sentry, contains an authentication bypass vulnerability that may allow an attacker to bypass authentication controls on the administrative interface due to an insufficiently restrictive Apache HTTPD configuration.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class SentryCve38035(CVEPlugin):
    cve_id = "CVE-2023-38035"
    product = "Sentry"
    severity = "critical"
    description = 'Ivanti Sentry, formerly known as MobileIron Sentry, contains an authentication bypass vulnerability that may allow an attacker to bypass authentication controls on the administrative interface due to '

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2023-38035
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "sentry"
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
