"""
CVE-2016-10033 — PHPMailer

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: PHPMailer contains a command injection vulnerability because it fails to sanitize user-supplied input. Specifically, this issue affects the 'mail()' function of 'class.phpmailer.php' script. An attacker can exploit this issue to execute arbitrary code within the context of the application. Failed exploit attempts will result in a denial-of-service condition.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class PhpmailerCve10033(CVEPlugin):
    cve_id = "CVE-2016-10033"
    product = "PHPMailer"
    severity = "critical"
    description = "PHPMailer contains a command injection vulnerability because it fails to sanitize user-supplied input. Specifically, this issue affects the 'mail()' function of 'class.phpmailer.php' script. An attack"

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2016-10033
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "phpmailer"
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
