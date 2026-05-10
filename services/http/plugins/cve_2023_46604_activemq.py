"""
CVE-2023-46604 — Apache ActiveMQ OpenWire RCE

Real ActiveMQ OpenWire protocol listens on tcp/61616, but attackers frequently
probe HTTP endpoints first (web console at /admin). This plugin catches the
web-console discovery and credential-spray phase: that signal alone is gold
for pre-attack warning.

For full OpenWire emulation, see services/tcp/activemq_openwire.py (future).
"""
from __future__ import annotations

from fastapi.responses import HTMLResponse, Response

from honeycore.plugins import CVEPlugin, PluginContext

_ADMIN_PATHS = ("/admin", "/admin/", "/admin/index.jsp",
                "/admin/queues.jsp", "/admin/login.jsp")


class ActiveMQAdminProbe(CVEPlugin):
    cve_id = "CVE-2023-46604"
    product = "Apache ActiveMQ"
    severity = "critical"
    description = "OpenWire unsafe deserialization → RCE. HTTP plugin catches the recon phase."

    def matches(self, ctx: PluginContext) -> bool:
        path = ctx.request.get("path", "").lower()
        ua = str((ctx.request.get("headers") or {}).get("user-agent", "")).lower()
        if any(path.startswith(p) for p in _ADMIN_PATHS):
            return True
        if "activemq" in ua or "openwire" in ua:
            return True
        return False

    def handle(self, ctx: PluginContext):
        path = ctx.request.get("path", "")
        headers = ctx.request.get("headers") or {}
        auth = headers.get("authorization")

        self.log_attempt(
            ctx,
            path=path,
            has_basic_auth=bool(auth and str(auth).lower().startswith("basic ")),
            authorization=str(auth) if auth else None,
            user_agent=headers.get("user-agent"),
        )

        # If no auth, return realistic 401 prompting basic auth (attackers
        # often follow up with credential spraying, which we'll also capture).
        if not auth:
            return Response(
                content="",
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="ActiveMQBroker"'},
            )

        # Authenticated probe — serve a look-alike landing page
        body = """<html><head><title>Apache ActiveMQ</title></head>
<body><h1>Welcome!</h1>
<p>Welcome to the Apache ActiveMQ Console of <b>localhost</b> (ID:broker-1)</p>
<p>Broker Name: localhost | Version: 5.17.3</p>
</body></html>"""
        return HTMLResponse(content=body, status_code=200)
