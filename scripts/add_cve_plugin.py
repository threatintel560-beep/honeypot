#!/usr/bin/env python3
"""
Scaffold a new CVE plugin.

Usage:
    python scripts/add_cve_plugin.py CVE-2024-12345 --service http [--product "Foo"]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

TEMPLATE = '''"""
{cve_id} — {product}

TODO: fill in exploitation flow.
"""
from __future__ import annotations

from fastapi.responses import HTMLResponse

from honeycore.plugins import CVEPlugin, PluginContext


class {class_name}(CVEPlugin):
    cve_id = "{cve_id}"
    product = "{product}"
    severity = "high"  # low | medium | high | critical
    description = "TODO: describe the vulnerability"

    def matches(self, ctx: PluginContext) -> bool:
        # TODO: cheap predicate. Return True when this plugin should handle the request.
        path = ctx.request.get("path", "")
        return path.startswith("/TODO-endpoint")

    def handle(self, ctx: PluginContext):
        # TODO: extract attacker payload from ctx.request
        self.log_attempt(ctx, payload="TODO")

        # TODO: return a realistic response
        return HTMLResponse(content="<html><body>OK</body></html>", status_code=200)
'''


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cve_id", help="e.g. CVE-2024-12345")
    ap.add_argument("--service", default="http", choices=["http", "ssh"])
    ap.add_argument("--product", default="TODO Product")
    args = ap.parse_args()

    if not re.match(r"^CVE-\d{4}-\d{4,7}$", args.cve_id, re.I):
        print(f"Invalid CVE ID format: {args.cve_id}", file=sys.stderr)
        return 2

    out_dir = Path(__file__).parent.parent / "services" / args.service / "plugins"
    out_dir.mkdir(parents=True, exist_ok=True)

    # cve_2024_12345_product_slug.py
    slug = re.sub(r"[^a-z0-9]+", "_", args.product.lower()).strip("_") or "plugin"
    filename = f"cve_{args.cve_id.split('-')[1]}_{args.cve_id.split('-')[2]}_{slug}.py"
    class_name = "".join(w.capitalize() for w in re.split(r"\W+", args.product) if w) or "Plugin"

    path = out_dir / filename
    if path.exists():
        print(f"Plugin already exists: {path}", file=sys.stderr)
        return 3

    path.write_text(TEMPLATE.format(
        cve_id=args.cve_id.upper(),
        product=args.product,
        class_name=class_name,
    ))
    print(f"Created {path}")
    print(f"Edit, then run: make reload-{args.service}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
