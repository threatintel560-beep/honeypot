"""
CVE-2023-36845 — Junos OS

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Juniper Junos OS on EX Series and SRX Series contains a PHP external variable modification vulnerability that allows an unauthenticated, network-based attacker to control an important environment variable. Using a crafted request, which sets the variable PHPRC, an attacker is able to modify the PHP execution environment allowing the injection und execution of code.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class JunosOsCve36845(CVEPlugin):
    cve_id = "CVE-2023-36845"
    product = "Junos OS"
    severity = "critical"
    description = 'Juniper Junos OS on EX Series and SRX Series contains a PHP external variable modification vulnerability that allows an unauthenticated, network-based attacker to control an important environment vari'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2023-36845
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "junos_os"
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
