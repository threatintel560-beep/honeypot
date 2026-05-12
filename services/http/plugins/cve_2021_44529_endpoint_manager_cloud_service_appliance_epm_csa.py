"""
CVE-2021-44529 — Endpoint Manager Cloud Service Appliance (EPM CSA)

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Ivanti Endpoint Manager Cloud Service Appliance (EPM CSA) contains a code injection vulnerability that allows an unauthenticated user to execute malicious code with limited permissions (nobody).
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class EndpointManagerCloudServiceApplianceEpmCsaCve44529(CVEPlugin):
    cve_id = "CVE-2021-44529"
    product = "Endpoint Manager Cloud Service Appliance (EPM CSA)"
    severity = "critical"
    description = 'Ivanti Endpoint Manager Cloud Service Appliance (EPM CSA) contains a code injection vulnerability that allows an unauthenticated user to execute malicious code with limited permissions (nobody).'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2021-44529
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "endpoint_manager_cloud_service_appliance_epm_csa"
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
