"""
CVE-2026-20122 — Catalyst SD-WAN Manger

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Cisco Catalyst SD-WAN Manager contains an incorrect use of privileged APIs vulnerability due to improper file handling on the API interface of an affected system. An attacker could exploit this vulnerability by uploading a malicious file on the local file system. A successful exploit could allow the attacker to overwrite arbitrary files on the affected system and gain vmanage user privileges.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class CatalystSdWanMangerCve20122(CVEPlugin):
    cve_id = "CVE-2026-20122"
    product = "Catalyst SD-WAN Manger"
    severity = "critical"
    description = 'Cisco Catalyst SD-WAN Manager contains an incorrect use of privileged APIs vulnerability due to improper file handling on the API interface of an affected system. An attacker could exploit this vulner'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2026-20122
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "catalyst_sd_wan_manger"
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
