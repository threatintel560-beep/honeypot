"""
CVE-2024-42009 — Webmail

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: RoundCube Webmail contains a cross-site scripting vulnerability. This vulnerability could allow a remote attacker to steal and send emails of a victim via a crafted e-mail message that abuses a Desanitization issue in message_body() in program/actions/mail/show.php.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class WebmailCve42009(CVEPlugin):
    cve_id = "CVE-2024-42009"
    product = "Webmail"
    severity = "critical"
    description = 'RoundCube Webmail contains a cross-site scripting vulnerability. This vulnerability could allow a remote attacker to steal and send emails of a victim via a crafted e-mail message that abuses a Desani'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2024-42009
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "webmail"
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
