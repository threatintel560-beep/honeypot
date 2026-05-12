"""
CVE-2025-32433 — Erlang/OTP

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: Erlang Erlang/OTP SSH server contains a missing authentication for critical function vulnerability. This could allow an attacker to execute arbitrary commands without valid credentials, potentially leading to unauthenticated remote code execution (RCE). By exploiting a flaw in how SSH protocol messages are handled, a malicious actor could gain unauthorized access to affected systems. This vulnerability could affect various products that implement Erlang/OTP SSH server, including—but not limited 
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class ErlangOtpCve32433(CVEPlugin):
    cve_id = "CVE-2025-32433"
    product = "Erlang/OTP"
    severity = "critical"
    description = 'Erlang Erlang/OTP SSH server contains a missing authentication for critical function vulnerability. This could allow an attacker to execute arbitrary commands without valid credentials, potentially le'

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2025-32433
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "erlang_otp"
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
