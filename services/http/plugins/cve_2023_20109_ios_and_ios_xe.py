"""
CVE-2023-20109 — IOS and IOS XE

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco IOS and IOS XE contain an out-of-bounds write vulnerability in the Group Encrypted Transport VPN (GET VPN) feature that could allow an authenticated, remote attacker who has administrative control of either a group member or a key server to execute malicious code or cause a device to crash.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class IosAndIosXeCve20109(CVEPlugin):
    cve_id = "CVE-2023-20109"
    product = "IOS and IOS XE"
    severity = "critical"
    description = 'Cisco IOS and IOS XE contain an out-of-bounds write vulnerability in the Group Encrypted Transport VPN (GET VPN) feature that could allow an authenticated, remote attacker who has administrative contr'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2023-20109
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "ios_and_ios_xe"
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
