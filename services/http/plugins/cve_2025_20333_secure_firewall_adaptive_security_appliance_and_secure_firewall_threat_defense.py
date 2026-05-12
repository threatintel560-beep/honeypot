"""
CVE-2025-20333 — Secure Firewall Adaptive Security Appliance and Secure Firewall Threat Defense

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco Secure Firewall Adaptive Security (ASA) Appliance and Secure Firewall Threat Defense (FTD) Software VPN Web Server contain a buffer overflow vulnerability that allows for remote code execution. This vulnerability could be chained with CVE-2025-20362.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class SecureFirewallAdaptiveSecurityApplianceAndSecureFirewallThreatDefenseCve20333(CVEPlugin):
    cve_id = "CVE-2025-20333"
    product = "Secure Firewall Adaptive Security Appliance and Secure Firewall Threat Defense"
    severity = "critical"
    description = 'Cisco Secure Firewall Adaptive Security (ASA) Appliance and Secure Firewall Threat Defense (FTD) Software VPN Web Server contain a buffer overflow vulnerability that allows for remote code execution. '

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2025-20333
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "secure_firewall_adaptive_security_appliance_and_secure_firewall_threat_defense"
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
