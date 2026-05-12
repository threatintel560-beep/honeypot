"""
CVE-2025-68645 —  Zimbra Collaboration Suite (ZCS)

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Synacor Zimbra Collaboration Suite (ZCS) contains a PHP remote file inclusion vulnerability that could allow for remote attackers to craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class ZimbraCollaborationSuiteZcsCve68645(CVEPlugin):
    cve_id = "CVE-2025-68645"
    product = " Zimbra Collaboration Suite (ZCS)"
    severity = "critical"
    description = 'Synacor Zimbra Collaboration Suite (ZCS) contains a PHP remote file inclusion vulnerability that could allow for remote attackers to craft requests to the /h/rest endpoint to influence internal reques'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2025-68645
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "zimbra_collaboration_suite_zcs"
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
