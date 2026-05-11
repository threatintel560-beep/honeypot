"""
CVE-2022-40684 — Multiple Products

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Fortinet FortiOS, FortiProxy, and FortiSwitchManager contain an authentication bypass vulnerability that could allow an unauthenticated attacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class MultipleProductsCve40684(CVEPlugin):
    cve_id = "CVE-2022-40684"
    product = "Multiple Products"
    severity = "critical"
    description = 'Fortinet FortiOS, FortiProxy, and FortiSwitchManager contain an authentication bypass vulnerability that could allow an unauthenticated attacker to perform operations on the administrative interface v'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2022-40684
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "multiple_products"
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
