"""
CVE-2023-36847 — Junos OS

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Juniper Junos OS on EX Series contains a missing authentication for critical function vulnerability that allows an unauthenticated, network-based attacker to cause limited impact to the file system integrity. With a specific request to installAppPackage.php that doesn't require authentication, an attacker is able to upload arbitrary files via J-Web, leading to a loss of integrity for a certain part of the file system, which may allow chaining to other vulnerabilities.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class JunosOsCve36847(CVEPlugin):
    cve_id = "CVE-2023-36847"
    product = "Junos OS"
    severity = "critical"
    description = 'Juniper Junos OS on EX Series contains a missing authentication for critical function vulnerability that allows an unauthenticated, network-based attacker to cause limited impact to the file system in'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2023-36847
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
