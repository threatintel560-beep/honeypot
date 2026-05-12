"""
CVE-2023-33246 — RocketMQ

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Several components of Apache RocketMQ, including NameServer, Broker, and Controller, are exposed to the extranet and lack permission verification. An attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as or achieve the same effect by forging the RocketMQ protocol content.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class RocketmqCve33246(CVEPlugin):
    cve_id = "CVE-2023-33246"
    product = "RocketMQ"
    severity = "critical"
    description = 'Several components of Apache RocketMQ, including NameServer, Broker, and Controller, are exposed to the extranet and lack permission verification. An attacker can exploit this vulnerability by using t'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2023-33246
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "rocketmq"
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
