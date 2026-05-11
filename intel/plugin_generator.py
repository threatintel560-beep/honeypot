"""
AI plugin generator — turn a CVE record into a draft CVEPlugin subclass.

Flow:
  1. Build a rich prompt from the CVE + the plugin authoring contract.
  2. Call the configured LLM backend (Ollama local / OpenAI-compatible).
  3. Extract the Python code from the response.
  4. Validate it compiles.
  5. If LLM fails or returns bad code, fall back to a deterministic template.

The generated plugin always goes through human review in the UI before
being promoted to services/http/plugins/ (status: draft → reviewed → deployed).
"""
from __future__ import annotations

import ast
import logging
import re
import textwrap
from pathlib import Path

from . import llm, storage
from .service_mapper import detect_service

log = logging.getLogger("intel.plugin_gen")

SYSTEM_PROMPT = """You are a senior offensive-security engineer building a high-interaction honeypot.

You write Python plugins that detect and log exploitation attempts for a specific CVE.
Your plugins emulate vulnerable services realistically — attackers must not be able
to tell this is a honeypot from the response alone.

You have deep knowledge of:
  - HTTP protocol internals
  - Common web vulnerabilities (RCE, SSTI, SSRF, deserialization, path traversal,
    auth bypass, file upload, SQL injection, command injection, JNDI/LDAP)
  - Typical exploit request shapes and response characteristics
  - MITRE ATT&CK techniques

You output ONLY runnable Python code — no prose, no markdown fences, no explanations.
"""

USER_TEMPLATE = """Generate a complete honeypot CVE plugin for: {cve_id}

CVE metadata
------------
Vendor:      {vendor}
Product:     {product}
Severity:    {severity}
CVSS:        {cvss}
Description: {description}
References:  {refs}

Plugin contract (REQUIRED)
--------------------------
```python
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from honeycore.plugins import CVEPlugin, PluginContext
import re

class {class_name}(CVEPlugin):
    cve_id      = "{cve_id}"
    product     = "{product}"
    severity    = "{severity_lc}"
    description = "<one-line summary>"

    def matches(self, ctx: PluginContext) -> bool:
        # Fast predicate. Inspect ctx.request dict which has keys:
        #   "method", "path", "query", "headers", "body" (bytes)
        # Return True ONLY when this request looks like CVE-{cve_id_num} exploitation.
        ...

    def handle(self, ctx: PluginContext):
        # 1. Parse attacker payload from the request
        # 2. Call self.log_attempt(ctx, **extras) with everything useful
        #    (extracted commands, dropper URLs, credentials, payload strings)
        # 3. Return a realistic response (match what a real vulnerable server returns)
        ...
```

Requirements
------------
1. Plugin MUST inherit from CVEPlugin and implement both methods.
2. matches() MUST be cheap — no network, no heavy regex compilation inside.
3. handle() MUST call self.log_attempt(ctx, ...) before returning.
4. Extract attacker intel: embedded URLs, base64 blobs, shell commands, credentials.
5. Response MUST look realistic — use Server/X-Powered-By headers the real product uses.
6. NEVER include strings like "honeypot", "cowrie", "fake", or framework defaults.
7. Import only from: honeycore.plugins, fastapi.responses, re, base64, json.
8. Code must be valid Python 3.12 and must compile.

Output: only the Python file contents — nothing else."""


FALLBACK_TEMPLATE = '''"""
{cve_id} — {product}

Auto-generated skeleton. REVIEW AND CUSTOMIZE before deploying.

CVSS:        {cvss}
Description: {description}
"""
from __future__ import annotations

import re

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext

URL_RE = re.compile(r'https?://[^\\s\\'"<>]+')


class {class_name}(CVEPlugin):
    cve_id = "{cve_id}"
    product = "{product}"
    severity = "{severity_lc}"
    description = {description_repr}

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: replace this with the real signature for {cve_id}
        path    = ctx.request.get("path", "").lower()
        query   = ctx.request.get("query", "")
        headers = ctx.request.get("headers") or {{}}
        body    = ctx.request.get("body", b"")
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        product_slug = "{product_slug}"
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
'''


# ── public API ──────────────────────────────────────────────────────
def generate(cve_id: str, service: str = "auto") -> tuple[str, str]:
    """
    Generate plugin code for a CVE. Returns (code, model_used).

    If service="auto", detects the correct service from CVE metadata.
    Raises ValueError if the CVE isn't in the intel DB.
    """
    storage.init_db()
    cve = storage.get_cve(cve_id)
    if not cve:
        raise ValueError(f"CVE not in DB: {cve_id}")

    # Auto-detect service from CVE product/description
    if service == "auto":
        service = detect_service(cve)

    cfg = storage.all_config()
    backend = llm.make_backend(cfg)

    class_name = _class_name(cve)
    ctx = {
        "cve_id":      cve_id,
        "cve_id_num":  cve_id.replace("CVE-", ""),
        "vendor":      cve.get("vendor") or "Unknown",
        "product":     cve.get("product") or "Unknown",
        "severity":    (cve.get("severity") or "high").capitalize(),
        "severity_lc": (cve.get("severity") or "high").lower(),
        "cvss":        cve.get("cvss") or "n/a",
        "description": (cve.get("description") or "")[:1200],
        "refs":        ", ".join((cve.get("refs_json") and __import__("json").loads(cve["refs_json"])) or [])[:500] or "none",
        "class_name":  class_name,
    }

    if backend.name == "template":
        return _fallback(cve, class_name), "template"

    user = USER_TEMPLATE.format(**ctx)
    try:
        raw = backend.generate(SYSTEM_PROMPT, user, max_tokens=2500)
        code = _extract_code(raw)
        if _valid_python(code) and _looks_like_plugin(code, class_name):
            return code, f"{backend.name}:{cfg.get('llm_model','?')}"
        log.warning("llm output rejected; falling back to template")
    except Exception as e:
        log.warning("llm call failed (%s); falling back to template", e)

    return _fallback(cve, class_name), "template"


def save_as_draft(cve_id: str, service: str, code: str, model_used: str) -> int:
    filename = _filename(cve_id, _guess_product_slug(cve_id))
    return storage.save_plugin(cve_id, service, filename, code, model_used)


def deploy_plugin(plugin_id: int, plugins_dir: str | Path = "/app/generated_plugins") -> Path:
    """Write the plugin to disk and mark it deployed.

    Operators are expected to bind-mount /app/generated_plugins to
    services/http/plugins on the host so the HTTP service picks it up
    after the next `make reload-http`.
    """
    p = storage.get_plugin(plugin_id)
    if not p:
        raise ValueError(f"plugin id {plugin_id} not found")
    out_dir = Path(plugins_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / p["filename"]
    path.write_text(p["code"])
    storage.update_plugin(plugin_id, status="deployed")
    storage.update_cve_status(p["cve_id"], "deployed")
    return path


# ── helpers ─────────────────────────────────────────────────────────
_CODE_FENCE_RE = re.compile(r"```(?:python)?\s*(.*?)```", re.DOTALL)


def _extract_code(raw: str) -> str:
    """Strip markdown fences, leading prose, etc."""
    if not raw:
        return ""
    m = _CODE_FENCE_RE.search(raw)
    if m:
        return m.group(1).strip()
    # If the response starts with prose before the first import/class, chop it
    lines = raw.splitlines()
    start = 0
    for i, line in enumerate(lines):
        if line.startswith(("import ", "from ", "#", '"""', "'''", "class ")):
            start = i
            break
    return "\n".join(lines[start:]).strip()


def _valid_python(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def _looks_like_plugin(code: str, class_name: str) -> bool:
    return ("CVEPlugin" in code
            and "def matches" in code
            and "def handle"  in code
            and class_name in code)


def _class_name(cve: dict) -> str:
    product = re.sub(r"[^A-Za-z0-9]+", " ", cve.get("product") or "").title().replace(" ", "")
    if not product:
        product = "Exploit"
    return f"{product}Cve{cve['cve_id'].split('-')[-1]}"


def _guess_product_slug(cve_id: str) -> str:
    cve = storage.get_cve(cve_id) or {}
    return re.sub(r"[^a-z0-9]+", "_", (cve.get("product") or "unknown").lower()).strip("_")


def _filename(cve_id: str, product_slug: str) -> str:
    parts = cve_id.split("-")
    return f"cve_{parts[1]}_{parts[2]}_{product_slug or 'plugin'}.py"


def _fallback(cve: dict, class_name: str) -> str:
    product_slug = re.sub(r"[^a-z0-9]+", "_", (cve.get("product") or "").lower()).strip("_") or "unknown"
    return FALLBACK_TEMPLATE.format(
        cve_id=cve["cve_id"],
        product=cve.get("product") or "Unknown",
        cvss=cve.get("cvss") or "n/a",
        description=(cve.get("description") or "")[:500],
        description_repr=repr((cve.get("description") or "")[:200]),
        severity_lc=(cve.get("severity") or "high").lower(),
        class_name=class_name,
        product_slug=product_slug,
    )
