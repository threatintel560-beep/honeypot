"""
CVE-2025-22224 — ESXi and Workstation

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: VMware ESXi and Workstation contain a time-of-check time-of-use (TOCTOU) race condition vulnerability that leads to an out-of-bounds write. Successful exploitation enables an attacker with local administrative privileges on a virtual machine to execute code as the virtual machine's VMX process running on the host.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class EsxiAndWorkstationCve22224(CVEPlugin):
    cve_id = "CVE-2025-22224"
    product = "ESXi and Workstation"
    severity = "critical"
    description = 'VMware ESXi and Workstation contain a time-of-check time-of-use (TOCTOU) race condition vulnerability that leads to an out-of-bounds write. Successful exploitation enables an attacker with local admin'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2025-22224
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "esxi_and_workstation"
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
