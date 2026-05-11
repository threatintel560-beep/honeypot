"""
CVE-2018-0147 — Secure Access Control System (ACS)

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: A vulnerability in Java deserialization used by Cisco Secure Access Control System (ACS) could allow an unauthenticated, remote attacker to execute arbitrary commands on an affected device. The vulnerability is due to insecure deserialization of user-supplied content by the affected software.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class SecureAccessControlSystemAcsCve0147(CVEPlugin):
    cve_id = "CVE-2018-0147"
    product = "Secure Access Control System (ACS)"
    severity = "critical"
    description = 'A vulnerability in Java deserialization used by Cisco Secure Access Control System (ACS) could allow an unauthenticated, remote attacker to execute arbitrary commands on an affected device. The vulner'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2018-0147
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "secure_access_control_system_acs"
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
