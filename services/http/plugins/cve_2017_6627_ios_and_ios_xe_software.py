"""
CVE-2017-6627 — IOS and IOS XE Software

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: A vulnerability in the UDP processing code of Cisco IOS and IOS XE could allow an unauthenticated, remote attacker to cause the input queue of an affected system to hold UDP packets, causing an interface queue wedge and denial of service.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class IosAndIosXeSoftwareCve6627(CVEPlugin):
    cve_id = "CVE-2017-6627"
    product = "IOS and IOS XE Software"
    severity = "critical"
    description = 'A vulnerability in the UDP processing code of Cisco IOS and IOS XE could allow an unauthenticated, remote attacker to cause the input queue of an affected system to hold UDP packets, causing an interf'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2017-6627
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "ios_and_ios_xe_software"
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
