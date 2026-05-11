"""
CVE-2022-22963 — Spring Cloud

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: When using routing functionality in VMware Tanzu's Spring Cloud Function, it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class SpringCloudCve22963(CVEPlugin):
    cve_id = "CVE-2022-22963"
    product = "Spring Cloud"
    severity = "critical"
    description = "When using routing functionality in VMware Tanzu's Spring Cloud Function, it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution"

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2022-22963
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "spring_cloud"
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
