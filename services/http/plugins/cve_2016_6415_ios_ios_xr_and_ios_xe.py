"""
CVE-2016-6415 — IOS, IOS XR, and IOS XE

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco IOS, IOS XR, and IOS XE contain insufficient condition checks in the part of the code that handles Internet Key Exchange version 1 (IKEv1) security negotiation requests. contains an information disclosure vulnerability in the Internet Key Exchange version 1 (IKEv1) that could allow an attacker to retrieve memory contents. Successful exploitation could allow the attacker to retrieve memory contents, which can lead to information disclosure.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class IosIosXrAndIosXeCve6415(CVEPlugin):
    cve_id = "CVE-2016-6415"
    product = "IOS, IOS XR, and IOS XE"
    severity = "critical"
    description = 'Cisco IOS, IOS XR, and IOS XE contain insufficient condition checks in the part of the code that handles Internet Key Exchange version 1 (IKEv1) security negotiation requests. contains an information '

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2016-6415
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "ios_ios_xr_and_ios_xe"
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
