"""
CVE-2020-13927 — Airflow's Experimental API

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        n/a
Description: The previous default setting for Airflow's Experimental API was to allow all API requests without authentication.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\s\'"<>]+')


class AirflowSExperimentalApiCve13927(CVEPlugin):
    cve_id = "CVE-2020-13927"
    product = "Airflow's Experimental API"
    severity = "critical"
    description = "The previous default setting for Airflow's Experimental API was to allow all API requests without authentication."

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for CVE-2020-13927
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "airflow_s_experimental_api"
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
