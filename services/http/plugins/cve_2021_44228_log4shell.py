"""
CVE-2021-44228 — Log4Shell

The vuln surface is any HTTP-reachable field that ends up logged through
log4j. Our deception: accept any request that carries a JNDI probe in a
header, URL, or body, respond 200 OK, and extract the callback URL as
threat intel.
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

JNDI_RE = re.compile(r"\$\{jndi:(ldap|ldaps|rmi|dns|iiop|nis|nds|corba|http)s?://[^}]+\}",
                     re.IGNORECASE)


class Log4Shell(CVEPlugin):
    cve_id = "CVE-2021-44228"
    product = "Apache Log4j 2.x"
    severity = "critical"
    description = "JNDI injection via log4j lookup in any logged string"

    def matches(self, ctx: PluginContext) -> bool:
        req = ctx.request
        haystacks = [
            req.get("path", ""),
            req.get("query", ""),
            req.get("body", b"").decode("utf-8", errors="replace") if req.get("body") else "",
        ]
        for v in (req.get("headers") or {}).values():
            haystacks.append(str(v))
        return any(JNDI_RE.search(h) for h in haystacks)

    def handle(self, ctx: PluginContext):
        req = ctx.request
        matches: list[str] = []
        for v in (req.get("headers") or {}).values():
            matches += JNDI_RE.findall(str(v))
        body_str = req.get("body", b"").decode("utf-8", errors="replace") if req.get("body") else ""
        for source in (req.get("path", ""), req.get("query", ""), body_str):
            matches += JNDI_RE.findall(source)

        # Extract the callback URL so SOCs can pivot on it
        payloads = []
        for pat in (req.get("path", ""), req.get("query", ""), body_str,
                    *[str(v) for v in (req.get("headers") or {}).values()]):
            for m in JNDI_RE.finditer(pat):
                payloads.append(m.group(0))

        self.log_attempt(
            ctx,
            payloads=payloads,
            protocols=sorted(set(matches)),
            source_fields=_where(req),
        )

        # Respond like a vulnerable vanilla Tomcat+Log4j app would:
        body = "<html><body><h1>Welcome</h1></body></html>"
        return HTMLResponse(content=body, status_code=200)


def _where(req: dict) -> list[str]:
    """Return list of fields that contained the JNDI pattern."""
    out = []
    body_str = req.get("body", b"").decode("utf-8", errors="replace") if req.get("body") else ""
    if JNDI_RE.search(req.get("path", "")): out.append("path")
    if JNDI_RE.search(req.get("query", "")): out.append("query")
    if JNDI_RE.search(body_str): out.append("body")
    for h, v in (req.get("headers") or {}).items():
        if JNDI_RE.search(str(v)):
            out.append(f"header:{h.lower()}")
    return out
