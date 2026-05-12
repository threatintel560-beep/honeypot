"""
CVE-2023-20273 — Cisco IOS XE Web UI

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco IOS XE contains a command injection vulnerability in the web user interface. When chained with CVE-2023-20198, the attacker can leverage the new local user to elevate privilege to root and write the implant to the file system. Cisco identified CVE-2023-20273 as the vulnerability exploited to deploy the implant. CVE-2021-1435, previously associated with the exploitation events, is no longer believed to be related to this activity.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class CiscoIosXeWebUiCve20273(CVEPlugin):
    cve_id = "CVE-2023-20273"
    product = "Cisco IOS XE Web UI"
    severity = "critical"
    description = 'Cisco IOS XE contains a command injection vulnerability in the web user interface. When chained with CVE-2023-20198, the attacker can leverage the new local user to elevate privilege to root and write'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2023-20273
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "cisco_ios_xe_web_ui"
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
