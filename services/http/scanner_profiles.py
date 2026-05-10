"""
Scanner-aware response profiles.

Censys, Shodan, and GreyNoise scanners probe every public IP. We want them
to see a realistic service — not flag us as a honeypot, but also capture
their probes as intelligence.

Strategy:
  - Detect known scanner User-Agents and source ASNs
  - Serve them pixel-perfect responses matching real services
  - Log the probe as a "recon_scan" event (separate from exploit attempts)
  - Never reveal honeypot indicators in scanner-facing responses

This module is imported by the HTTP server and checked before plugin dispatch.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Known scanner signatures
SCANNER_UA_PATTERNS = [
    (re.compile(r"CensysInspect", re.I), "censys"),
    (re.compile(r"Censys", re.I), "censys"),
    (re.compile(r"Shodan", re.I), "shodan"),
    (re.compile(r"ZmEu", re.I), "zmeu"),
    (re.compile(r"Nmap", re.I), "nmap"),
    (re.compile(r"masscan", re.I), "masscan"),
    (re.compile(r"zgrab", re.I), "zgrab"),
    (re.compile(r"GreyNoise", re.I), "greynoise"),
    (re.compile(r"NetcraftSurveyAgent", re.I), "netcraft"),
    (re.compile(r"internetmeasur", re.I), "research"),
    (re.compile(r"research|scanner|crawl", re.I), "generic_scanner"),
]

# Known scanner IP ranges (partial — extend with ASN lookups in production)
SCANNER_IP_PREFIXES = [
    # Censys
    "162.142.125.", "167.94.138.", "167.94.145.", "167.94.146.",
    "167.248.133.", "199.45.154.", "199.45.155.",
    # Shodan
    "71.6.135.", "71.6.146.", "71.6.158.", "71.6.165.",
    "66.240.192.", "66.240.236.", "82.221.105.", "85.25.43.",
    "93.120.27.", "188.138.9.", "198.20.69.", "198.20.70.",
    "198.20.71.", "198.20.99.",
    # GreyNoise
    "35.203.", "35.192.", "35.232.",
    # Stretchoid
    "198.235.24.",
    # BinaryEdge
    "37.9.175.",
]


@dataclass
class ScannerInfo:
    """Detected scanner metadata."""
    name: str
    is_scanner: bool
    source: str  # "user_agent" or "ip_prefix"


def detect_scanner(src_ip: str, headers: dict[str, Any]) -> ScannerInfo | None:
    """
    Check if a request comes from a known internet scanner.
    Returns ScannerInfo if detected, None otherwise.
    """
    ua = str(headers.get("user-agent", ""))

    # Check User-Agent patterns
    for pattern, name in SCANNER_UA_PATTERNS:
        if pattern.search(ua):
            return ScannerInfo(name=name, is_scanner=True, source="user_agent")

    # Check IP prefixes
    for prefix in SCANNER_IP_PREFIXES:
        if src_ip.startswith(prefix):
            return ScannerInfo(name="ip_match", is_scanner=True, source="ip_prefix")

    return None


# ── Realistic response templates for scanner probes ────────────────
# These match what real services return, preventing honeypot fingerprinting.

APACHE_DEFAULT = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>Apache2 Ubuntu Default Page: It works</title>
</head><body>
<h1>It works!</h1>
<p>This is the default welcome page used to test the correct operation of the Apache2 server after installation on Ubuntu systems. It is based on the equivalent page on Debian, from which the Ubuntu Apache packaging is derived.</p>
<p>If you can read this page, it means that the Apache HTTP server installed at this site is working properly. You should <b>replace this file</b> (located at <tt>/var/www/html/index.html</tt>) before continuing to operate your HTTP server.</p>
</body></html>"""

NGINX_DEFAULT = """<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>"""

IIS_DEFAULT = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS Windows Server</title>
<style type="text/css">body{margin:0;font-size:.7em;font-family:Verdana,Arial,Helvetica,sans-serif;}</style>
</head>
<body>
<div id="container"><a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="iisstart.png" alt="IIS" width="960" height="600" /></a></div>
</body>
</html>"""

# Map server header patterns to default pages
_SERVER_PAGE_MAP = {
    "apache": APACHE_DEFAULT,
    "nginx": NGINX_DEFAULT,
    "iis": IIS_DEFAULT,
    "microsoft": IIS_DEFAULT,
}


def get_default_page(server_header: str) -> str:
    """Return the appropriate default page based on the Server header."""
    server_lower = server_header.lower()
    for key, page in _SERVER_PAGE_MAP.items():
        if key in server_lower:
            return page
    return APACHE_DEFAULT


# Common paths that scanners probe and expected responses
SCANNER_PATHS: dict[str, tuple[int, str, str]] = {
    # (status_code, content_type, body)
    "/robots.txt": (200, "text/plain", "User-agent: *\nDisallow: /admin/\nDisallow: /wp-admin/\n"),
    "/favicon.ico": (404, "text/html", "<html><body><h1>Not Found</h1></body></html>"),
    "/.well-known/security.txt": (404, "text/plain", "Not Found"),
    "/server-status": (403, "text/html", "<html><body><h1>Forbidden</h1><p>You don't have permission to access this resource.</p></body></html>"),
    "/wp-login.php": (200, "text/html", '<html><head><title>Log In &lsaquo; WordPress</title></head><body class="login"><div id="login"><h1><a href="https://wordpress.org/">Powered by WordPress</a></h1><form name="loginform" id="loginform" action="/wp-login.php" method="post"><p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login" /></p><p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass" /></p><p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In" /></p></form></div></body></html>'),
}
