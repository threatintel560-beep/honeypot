"""
CVE-2020-28949 — Archive_Tar

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: PEAR Archive_Tar allows an unserialization attack because phar: is blocked but PHAR: is not blocked. PEAR stands for PHP Extension and Application Repository and it is an open-source framework and distribution system for reusable PHP components with known usage in third-party products such as Drupal Core and Red Hat Linux.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class ArchiveTarCve28949(CVEPlugin):
    cve_id = "CVE-2020-28949"
    product = "Archive_Tar"
    severity = "critical"
    description = 'PEAR Archive_Tar allows an unserialization attack because phar: is blocked but PHAR: is not blocked. PEAR stands for PHP Extension and Application Repository and it is an open-source framework and dis'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2020-28949
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "archive_tar"
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
