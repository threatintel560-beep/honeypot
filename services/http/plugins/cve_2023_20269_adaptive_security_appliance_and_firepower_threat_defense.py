"""
CVE-2023-20269 — Adaptive Security Appliance and Firepower Threat Defense

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco Adaptive Security Appliance and Firepower Threat Defense contain an unauthorized access vulnerability that could allow an unauthenticated, remote attacker to conduct a brute force attack in an attempt to identify valid username and password combinations or establish a clientless SSL VPN session with an unauthorized user.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class AdaptiveSecurityApplianceAndFirepowerThreatDefenseCve20269(CVEPlugin):
    cve_id = "CVE-2023-20269"
    product = "Adaptive Security Appliance and Firepower Threat Defense"
    severity = "critical"
    description = 'Cisco Adaptive Security Appliance and Firepower Threat Defense contain an unauthorized access vulnerability that could allow an unauthenticated, remote attacker to conduct a brute force attack in an a'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2023-20269
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "adaptive_security_appliance_and_firepower_threat_defense"
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
