"""
CVE-2024-37079 — VMware vCenter Server

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Broadcom VMware vCenter Server contains an out-of-bounds write vulnerability in the implementation of the DCERPC protocol. This could allow a malicious actor with network access to vCenter Server to send specially crafted network packets, potentially leading to remote code execution.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class VmwareVcenterServerCve37079(CVEPlugin):
    cve_id = "CVE-2024-37079"
    product = "VMware vCenter Server"
    severity = "critical"
    description = 'Broadcom VMware vCenter Server contains an out-of-bounds write vulnerability in the implementation of the DCERPC protocol. This could allow a malicious actor with network access to vCenter Server to s'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2024-37079
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "vmware_vcenter_server"
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
