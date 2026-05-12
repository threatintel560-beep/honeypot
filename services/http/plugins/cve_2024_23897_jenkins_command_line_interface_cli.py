"""
CVE-2024-23897 — Jenkins Command Line Interface (CLI)

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Jenkins Command Line Interface (CLI) contains a path traversal vulnerability that allows attackers limited read access to certain files, which can lead to code execution.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class JenkinsCommandLineInterfaceCliCve23897(CVEPlugin):
    cve_id = "CVE-2024-23897"
    product = "Jenkins Command Line Interface (CLI)"
    severity = "critical"
    description = 'Jenkins Command Line Interface (CLI) contains a path traversal vulnerability that allows attackers limited read access to certain files, which can lead to code execution.'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2024-23897
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "jenkins_command_line_interface_cli"
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
