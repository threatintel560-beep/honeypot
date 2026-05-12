"""
CVE-2024-20353 — Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) contain an infinite loop vulnerability that can lead to remote denial of service condition.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class AdaptiveSecurityApplianceAsaAndFirepowerThreatDefenseFtdCve20353(CVEPlugin):
    cve_id = "CVE-2024-20353"
    product = "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)"
    severity = "critical"
    description = 'Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) contain an infinite loop vulnerability that can lead to remote denial of service condition.'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2024-20353
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "adaptive_security_appliance_asa_and_firepower_threat_defense_ftd"
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
