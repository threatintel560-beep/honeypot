"""
CVE-2024-8963 — Cloud Services Appliance (CSA)

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Ivanti Cloud Services Appliance (CSA) contains a path traversal vulnerability that could allow a remote, unauthenticated attacker to access restricted functionality. If CVE-2024-8963 is used in conjunction with CVE-2024-8190, an attacker could bypass admin authentication and execute arbitrary commands on the appliance.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class CloudServicesApplianceCsaCve8963(CVEPlugin):
    cve_id = "CVE-2024-8963"
    product = "Cloud Services Appliance (CSA)"
    severity = "critical"
    description = 'Ivanti Cloud Services Appliance (CSA) contains a path traversal vulnerability that could allow a remote, unauthenticated attacker to access restricted functionality. If CVE-2024-8963 is used in conjun'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2024-8963
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "cloud_services_appliance_csa"
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
