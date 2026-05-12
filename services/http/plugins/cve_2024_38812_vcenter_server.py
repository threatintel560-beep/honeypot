"""
CVE-2024-38812 — vCenter Server

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: VMware vCenter Server contains a heap-based buffer overflow vulnerability in the implementation of the DCERPC protocol. This vulnerability could allow an attacker with network access to the vCenter Server to execute remote code by sending a specially crafted packet.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class VcenterServerCve38812(CVEPlugin):
    cve_id = "CVE-2024-38812"
    product = "vCenter Server"
    severity = "critical"
    description = 'VMware vCenter Server contains a heap-based buffer overflow vulnerability in the implementation of the DCERPC protocol. This vulnerability could allow an attacker with network access to the vCenter Se'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2024-38812
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "vcenter_server"
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
