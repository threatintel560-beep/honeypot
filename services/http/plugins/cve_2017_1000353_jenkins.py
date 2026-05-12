"""
CVE-2017-1000353 — Jenkins

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Jenkins contains a remote code execution vulnerability. This vulnerability that could allowed attackers to transfer a serialized Java SignedObject object to the remoting-based Jenkins CLI, that would be deserialized using a new ObjectInputStream, bypassing the existing blocklist-based protection mechanism.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class JenkinsCve1000353(CVEPlugin):
    cve_id = "CVE-2017-1000353"
    product = "Jenkins"
    severity = "critical"
    description = 'Jenkins contains a remote code execution vulnerability. This vulnerability that could allowed attackers to transfer a serialized Java SignedObject object to the remoting-based Jenkins CLI, that would '

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2017-1000353
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "jenkins"
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
