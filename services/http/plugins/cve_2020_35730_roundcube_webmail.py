"""
CVE-2020-35730 — Roundcube Webmail

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Roundcube Webmail contains a cross-site scripting (XSS) vulnerability that allows an attacker to send a plain text e-mail message with Javascript in a link reference element that is mishandled by linkref_addinindex in rcube_string_replacer.php.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class RoundcubeWebmailCve35730(CVEPlugin):
    cve_id = "CVE-2020-35730"
    product = "Roundcube Webmail"
    severity = "critical"
    description = 'Roundcube Webmail contains a cross-site scripting (XSS) vulnerability that allows an attacker to send a plain text e-mail message with Javascript in a link reference element that is mishandled by link'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2020-35730
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "roundcube_webmail"
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
