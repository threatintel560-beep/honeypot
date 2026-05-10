"""
CVE-2024-4577 — PHP-CGI Argument Injection (Windows)

Affected: PHP 8.x < 8.3.8, 8.2.x < 8.2.20, 8.1.x < 8.1.29 on Windows
CVSS:     9.8 Critical
Summary:  Argument injection via URL encoding bypass in PHP-CGI mode.
          Allows remote code execution without authentication.
PoC:      GET /index.php?%ADd+allow_url_include=1+%ADd+auto_prepend_file=php://input
          Body: <?php system("id"); ?>

What we capture:
  - The injected query string arguments
  - The PHP payload (commands the attacker wants to run)
  - Any dropper URLs embedded in the payload
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

# Patterns that identify CVE-2024-4577 exploitation attempts
_INJECTION_PATTERNS = [
    "allow_url_include",    # core argument injection marker
    "auto_prepend_file",    # secondary payload delivery mechanism
    "%ADd",                 # URL-encoded soft-hyphen argument prefix
    "%ad",                  # lowercase variant
]

URL_RE = re.compile(r'https?://[^\s\'"<>]+')
CMD_RE = re.compile(r'system\s*\(\s*["\']([^"\']+)["\']')


class PhpCgiArgumentInjection(CVEPlugin):
    cve_id = "CVE-2024-4577"
    product = "PHP-CGI"
    severity = "critical"
    description = "Argument injection in PHP-CGI on Windows → unauthenticated RCE"

    def matches(self, ctx: PluginContext) -> bool:
        """
        Trigger on any request that carries the PHP-CGI injection signature.
        Checks: URL query string, request body, path.
        """
        query = ctx.request.get("query", "")
        path  = ctx.request.get("path",  "")
        body  = ctx.request.get("body",  b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        haystack = f"{path} {query} {body}"

        # Match if any known injection marker is present
        if any(p in haystack for p in _INJECTION_PATTERNS):
            return True

        # Also catch raw PHP payloads sent to .php endpoints
        if "<?php" in body and path.endswith(".php"):
            return True

        return False

    def handle(self, ctx: PluginContext):
        """
        Log the full attacker payload and return a realistic PHP-CGI response.
        Real vulnerable servers execute the PHP and return stdout — we fake
        plausible output to keep the attacker engaged and logging.
        """
        query  = ctx.request.get("query", "")
        method = ctx.request.get("method", "GET")
        body   = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        # ── Extract intel from the payload ──────────────────────────
        # PHP commands: system("..."), exec("..."), shell_exec("...")
        commands = CMD_RE.findall(body)

        # Dropper URLs embedded in curl/wget commands inside the payload
        dropper_urls = URL_RE.findall(body)

        # Raw PHP payload (cap at 4KB so logs don't bloat)
        php_payload = body[:4096].strip() if "<?php" in body else None

        # ── Log everything ───────────────────────────────────────────
        self.log_attempt(
            ctx,
            method=method,
            query_string=query,
            php_payload=php_payload,
            injected_commands=commands,
            dropper_urls=dropper_urls,
        )

        # ── Return realistic output ──────────────────────────────────
        # A real vulnerable server running as www-data would return the
        # stdout of the executed command. We return convincing fake output.
        fake_output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"

        return HTMLResponse(
            content=fake_output,
            status_code=200,
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "X-Powered-By":  "PHP/8.1.2",
            },
        )
