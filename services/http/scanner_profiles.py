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

    # ── WordPress ─────────────────────────────────────────────────
    "/wp-login.php": (200, "text/html", '<html><head><title>Log In &lsaquo; WordPress</title></head><body class="login"><div id="login"><h1><a href="https://wordpress.org/">Powered by WordPress</a></h1><form name="loginform" id="loginform" action="/wp-login.php" method="post"><p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login" /></p><p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass" /></p><p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In" /></p></form></div></body></html>'),
    "/wp-admin/": (302, "text/html", ""),
    "/xmlrpc.php": (405, "text/plain", "XML-RPC server accepts POST requests only."),

    # ── ManageEngine ServiceDesk / Desktop Central ────────────────
    "/WOLogin.do": (200, "text/html", '<!DOCTYPE html><html><head><title>ManageEngine ServiceDesk Plus :: Login</title><style>body{font-family:Roboto,Arial;background:#f0f2f5;margin:0}.login-box{width:400px;margin:80px auto;background:#fff;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);padding:40px}h1{color:#d32f2f;font-size:20px;text-align:center}input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}button{width:100%;padding:12px;background:#d32f2f;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px}</style></head><body><div class="login-box"><h1>ManageEngine ServiceDesk Plus</h1><form method="POST" action="/j_security_check"><input name="j_username" placeholder="User Name"><input name="j_password" type="password" placeholder="Password"><input name="DOMAIN_NAME" type="hidden" value="AD_AUTH"><button>LOGIN</button></form></div></body></html>'),
    "/j_security_check": (302, "text/html", ""),
    "/fileupload": (200, "text/html", "<html><body>Upload successful</body></html>"),
    "/api/json/admin": (401, "application/json", '{"response":{"status":"failed","message":"Authentication required"}}'),
    "/SetupWizard.do": (200, "text/html", '<!DOCTYPE html><html><head><title>ManageEngine - Setup</title></head><body><h2>ManageEngine Setup Wizard</h2><p>Initial configuration required.</p></body></html>'),

    # ── Jenkins ───────────────────────────────────────────────────
    "/login": (200, "text/html", '<!DOCTYPE html><html><head><title>Sign in [Jenkins]</title><style>body{font-family:sans-serif;background:#f0f0f0;margin:0}#page-body{width:400px;margin:60px auto}h1{color:#333;font-size:24px}form{background:#fff;padding:30px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1)}input{width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:3px;box-sizing:border-box}button{padding:10px 20px;background:#4b758b;color:#fff;border:none;border-radius:3px;cursor:pointer}</style></head><body><div id="page-body"><h1>Sign in to Jenkins</h1><form method="POST" action="/j_spring_security_check"><input name="j_username" placeholder="User"><input name="j_password" type="password" placeholder="Password"><button>Sign in</button></form></div></body></html>'),
    "/api/json": (403, "text/html", "<html><body><h2>HTTP ERROR 403 Forbidden</h2></body></html>"),
    "/script": (403, "text/html", "<html><body><h2>HTTP ERROR 403 Forbidden</h2></body></html>"),
    "/cli": (200, "text/plain", "Jenkins CLI\nUsage: java -jar jenkins-cli.jar [-s URL] command [opts...] args...\n"),

    # ── FortiGate (also on port 80) ──────────────────────────────
    "/remote/login": (200, "text/html", '<!DOCTYPE html><html><head><title>FortiGate SSL-VPN</title><style>body{font-family:Arial;background:#f5f5f5;margin:0}.login{width:400px;margin:80px auto;background:#fff;border-radius:4px;box-shadow:0 2px 8px rgba(0,0,0,.1);padding:40px;text-align:center}h2{color:#333}input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:3px;box-sizing:border-box}button{width:100%;padding:12px;background:#c00;color:#fff;border:none;border-radius:3px;cursor:pointer}</style></head><body><div class="login"><h2>SSL-VPN Login</h2><form method="POST" action="/remote/logincheck"><input name="username" placeholder="Username"><input name="credential" type="password" placeholder="Password"><button>Login</button></form></div></body></html>'),
    "/remote/logincheck": (401, "text/html", '<html><body><script>document.location="/remote/login?err=1";</script></body></html>'),
    "/api/v2/cmdb/system/status": (401, "application/json", '{"http_status":401,"revision":"","serial":"FGT60F0000000000","version":"v7.4.4","build":2573}'),

    # ── Palo Alto GlobalProtect ───────────────────────────────────
    "/global-protect/login.esp": (200, "text/html", '<!DOCTYPE html><html><head><title>GlobalProtect Portal</title><style>body{font-family:Arial;background:#1a237e;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:#fff;border-radius:8px;padding:40px;width:380px;text-align:center}h1{font-size:16px;color:#333}input{width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}button{width:100%;padding:12px;background:#1565c0;color:#fff;border:none;border-radius:4px;cursor:pointer}</style></head><body><div class="card"><h1>GlobalProtect Portal</h1><form method="POST"><input name="user" placeholder="Username"><input name="passwd" type="password" placeholder="Password"><button>Sign In</button></form></div></body></html>'),
    "/ssl-vpn/hipreport.esp": (200, "text/html", "<html><body>OK</body></html>"),

    # ── Citrix NetScaler / Gateway ────────────────────────────────
    "/vpn/index.html": (200, "text/html", '<!DOCTYPE html><html><head><title>Citrix Gateway</title><style>body{font-family:Arial;background:#002b49;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:#fff;border-radius:8px;padding:40px;width:400px}h1{color:#002b49;text-align:center;font-size:18px}input{width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}button{width:100%;padding:12px;background:#002b49;color:#fff;border:none;border-radius:4px;cursor:pointer}</style></head><body><div class="card"><h1>Citrix Gateway - Log On</h1><form method="POST" action="/cgi/login"><input name="login" placeholder="User name"><input name="passwd" type="password" placeholder="Password"><button>Log On</button></form></div></body></html>'),
    "/cgi/login": (302, "text/html", ""),

    # ── Ivanti Connect Secure / Pulse Secure ──────────────────────
    "/dana-na/auth/url_default/welcome.cgi": (200, "text/html", '<!DOCTYPE html><html><head><title>Ivanti Connect Secure</title><style>body{font-family:Arial;background:#1a1a2e;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:#16213e;border-radius:8px;padding:40px;width:380px}h2{color:#fff;text-align:center}input{width:100%;padding:10px;margin:8px 0;border:1px solid #333;border-radius:4px;background:#0f3460;color:#fff;box-sizing:border-box}button{width:100%;padding:12px;background:#e94560;color:#fff;border:none;border-radius:4px;cursor:pointer}</style></head><body><div class="card"><h2>Sign In</h2><form method="POST" action="/dana-na/auth/url_default/login.cgi"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button>Sign In</button></form></div></body></html>'),
    "/dana-na/auth/url_default/login.cgi": (302, "text/html", ""),

    # ── Zoho / ManageEngine ADSelfService ─────────────────────────
    "/showLogin.cc": (200, "text/html", '<!DOCTYPE html><html><head><title>ADSelfService Plus</title><style>body{font-family:Roboto,Arial;background:#f5f5f5;margin:0}.login{width:400px;margin:80px auto;background:#fff;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);padding:40px}h1{color:#2196F3;text-align:center;font-size:18px}input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}button{width:100%;padding:12px;background:#2196F3;color:#fff;border:none;border-radius:4px;cursor:pointer}</style></head><body><div class="login"><h1>ADSelfService Plus</h1><form method="POST" action="/j_security_check"><input name="j_username" placeholder="Username"><input name="j_password" type="password" placeholder="Password"><button>Log In</button></form></div></body></html>'),

    # ── Atlassian Confluence ──────────────────────────────────────
    "/login.action": (200, "text/html", '<!DOCTYPE html><html><head><title>Log In - Confluence</title><style>body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#f4f5f7;margin:0}.login{width:400px;margin:80px auto;background:#fff;border-radius:3px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:40px}h1{color:#172b4d;font-size:20px;text-align:center}input{width:100%;padding:10px;margin:8px 0;border:1px solid #dfe1e6;border-radius:3px;box-sizing:border-box}button{width:100%;padding:10px;background:#0052cc;color:#fff;border:none;border-radius:3px;cursor:pointer}</style></head><body><div class="login"><h1>Log in to Confluence</h1><form method="POST" action="/dologin.action"><input name="os_username" placeholder="Username"><input name="os_password" type="password" placeholder="Password"><button>Log in</button></form></div></body></html>'),
    "/rest/api/content": (401, "application/json", '{"statusCode":401,"message":"User is not authenticated."}'),

    # ── Atlassian Jira ────────────────────────────────────────────
    "/secure/Dashboard.jspa": (302, "text/html", ""),
    "/rest/api/2/serverInfo": (200, "application/json", '{"baseUrl":"http://localhost","version":"9.4.1","buildNumber":940001,"serverTitle":"Jira"}'),

    # ── GitLab ────────────────────────────────────────────────────
    "/users/sign_in": (200, "text/html", '<!DOCTYPE html><html><head><title>Sign in · GitLab</title><style>body{font-family:-apple-system,sans-serif;background:#fafafa;margin:0}.login{width:400px;margin:80px auto;background:#fff;border-radius:4px;box-shadow:0 1px 4px rgba(0,0,0,.1);padding:40px}h1{color:#292961;text-align:center;font-size:20px}input{width:100%;padding:10px;margin:8px 0;border:1px solid #dbdbdb;border-radius:4px;box-sizing:border-box}button{width:100%;padding:10px;background:#6b4fbb;color:#fff;border:none;border-radius:4px;cursor:pointer}</style></head><body><div class="login"><h1>GitLab</h1><form method="POST" action="/users/sign_in"><input name="user[login]" placeholder="Username or email"><input name="user[password]" type="password" placeholder="Password"><button>Sign in</button></form></div></body></html>'),
    "/api/v4/projects": (401, "application/json", '{"message":"401 Unauthorized"}'),

    # ── VMware vCenter ────────────────────────────────────────────
    "/ui/login": (200, "text/html", '<!DOCTYPE html><html><head><title>vSphere Client</title><style>body{font-family:Arial;background:#1a2a3a;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:#fff;border-radius:4px;padding:40px;width:380px;text-align:center}h1{color:#1a2a3a;font-size:18px}input{width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:3px;box-sizing:border-box}button{width:100%;padding:12px;background:#0073e7;color:#fff;border:none;border-radius:3px;cursor:pointer}</style></head><body><div class="card"><h1>VMware vSphere</h1><form method="POST"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button>Login</button></form></div></body></html>'),
    "/sdk": (200, "text/xml", '<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><RetrieveServiceContentResponse><returnval><about><name>VMware vCenter Server</name><version>8.0.2</version><build>22617221</build></about></returnval></RetrieveServiceContentResponse></soapenv:Body></soapenv:Envelope>'),

    # ── Apache Solr ───────────────────────────────────────────────
    "/solr/admin/info/system": (200, "application/json", '{"responseHeader":{"status":0},"lucene":{"solr-spec-version":"9.4.0"},"jvm":{"version":"11.0.20"},"system":{"name":"Linux"}}'),
    "/solr/": (200, "text/html", '<html><head><title>Solr Admin</title></head><body><h1>Solr Admin</h1></body></html>'),

    # ── Spring Boot Actuator ──────────────────────────────────────
    "/actuator": (200, "application/json", '{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"},"env":{"href":"/actuator/env"},"beans":{"href":"/actuator/beans"}}}'),
    "/actuator/env": (200, "application/json", '{"activeProfiles":["production"],"propertySources":[{"name":"systemProperties"}]}'),
    "/actuator/health": (200, "application/json", '{"status":"UP"}'),

    # ── Apache Struts ─────────────────────────────────────────────
    "/struts/webconsole.html": (200, "text/html", '<html><head><title>Struts Problem Report</title></head><body><h2>Struts Problem Report</h2><p>Development mode enabled.</p></body></html>'),

    # ── PHPMyAdmin ────────────────────────────────────────────────
    "/phpmyadmin/": (200, "text/html", '<!DOCTYPE html><html><head><title>phpMyAdmin</title><style>body{font-family:sans-serif;background:#f3f3f3;margin:0}.login{width:400px;margin:60px auto;background:#fff;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:30px}h1{color:#333;font-size:18px;text-align:center}input{width:100%;padding:8px;margin:6px 0;border:1px solid #ccc;border-radius:3px;box-sizing:border-box}button{padding:8px 16px;background:#f60;color:#fff;border:none;border-radius:3px;cursor:pointer}</style></head><body><div class="login"><h1>phpMyAdmin</h1><form method="POST" action="/phpmyadmin/index.php"><input name="pma_username" placeholder="Username"><input name="pma_password" type="password" placeholder="Password"><button>Go</button></form></div></body></html>'),

    # ── Exchange / OWA ────────────────────────────────────────────
    "/owa/auth/logon.aspx": (200, "text/html", '<!DOCTYPE html><html><head><title>Outlook Web App</title><style>body{font-family:Segoe UI,Arial;background:#0078d4;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:#fff;border-radius:4px;padding:40px;width:380px}h1{color:#333;font-size:18px;text-align:center}input{width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:3px;box-sizing:border-box}button{width:100%;padding:12px;background:#0078d4;color:#fff;border:none;border-radius:3px;cursor:pointer}</style></head><body><div class="card"><h1>Outlook Web App</h1><form method="POST" action="/owa/auth.owa"><input name="username" placeholder="domain\\username"><input name="password" type="password" placeholder="Password"><button>Sign in</button></form></div></body></html>'),
    "/autodiscover/autodiscover.xml": (401, "text/html", "<html><body><h1>401 Unauthorized</h1></body></html>"),
    "/ecp/": (302, "text/html", ""),
}

