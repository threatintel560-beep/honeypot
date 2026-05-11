"""
CVE-2021-21973 — vCenter Server and Cloud Foundation

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: VMware vCenter Server and Cloud Foundation Server contain a SSRF vulnerability due to improper validation of URLs in a vCenter Server plugin. This allows for information disclosure.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class VcenterServerAndCloudFoundationCve21973(CVEPlugin):
    cve_id = "CVE-2021-21973"
    product = "vCenter Server and Cloud Foundation"
    severity = "critical"
    description = 'VMware vCenter Server and Cloud Foundation Server contain a SSRF vulnerability due to improper validation of URLs in a vCenter Server plugin. This allows for information disclosure.'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2021-21973
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "vcenter_server_and_cloud_foundation"
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
