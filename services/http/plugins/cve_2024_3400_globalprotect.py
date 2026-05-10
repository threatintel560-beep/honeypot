"""
CVE-2024-3400 — Palo Alto GlobalProtect command injection.

Trigger: crafted SESSID cookie on /ssl-vpn/ paths allows OS command injection.
We catch the probe and log the injected command string.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

INJECTION_RE = re.compile(r"[`$(|;&]|/\.\./|/tmp/")


class GlobalProtectInjection(CVEPlugin):
    cve_id = "CVE-2024-3400"
    product = "Palo Alto GlobalProtect"
    severity = "critical"
    description = "Arbitrary command execution via SESSID cookie on /ssl-vpn/*"

    def matches(self, ctx: PluginContext) -> bool:
        path = ctx.request.get("path", "").lower()
        if not path.startswith("/ssl-vpn") and not path.startswith("/global-protect"):
            return False
        cookies = str((ctx.request.get("headers") or {}).get("cookie", ""))
        return "SESSID=" in cookies

    def handle(self, ctx: PluginContext):
        cookies = str((ctx.request.get("headers") or {}).get("cookie", ""))
        sessid = _extract_sessid(cookies)
        suspicious = bool(sessid and INJECTION_RE.search(sessid))

        self.log_attempt(
            ctx,
            sessid=sessid,
            suspicious=suspicious,
            raw_cookie=cookies,
        )

        # Realistic GlobalProtect portal response
        body = """<html><head><title>GlobalProtect Portal</title></head>
<body><h2>GlobalProtect Portal</h2>
<form method="POST" action="/global-protect/login.esp">
  <input name="user"><input name="passwd" type="password">
  <input type="submit" value="Login">
</form></body></html>"""
        return HTMLResponse(content=body, status_code=200)


def _extract_sessid(cookie_header: str) -> str | None:
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if pair.upper().startswith("SESSID="):
            return pair.split("=", 1)[1]
    return None
