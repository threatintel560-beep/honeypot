"""
Product profiles — make the honeypot look like a specific product on scan.

Each profile defines:
  - Server header (what Censys/Shodan see)
  - Default page HTML (what scanners index)
  - Common paths and their responses
  - TLS cert CN (if applicable)

Usage: set HONEYPOT_PRODUCT=fortinet in the container env.
The server will then respond as FortiGate on every request that
doesn't match a CVE plugin.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

PRODUCT_PROFILES: dict[str, "ProductProfile"] = {}


@dataclass
class ProductProfile:
    """Defines how the honeypot impersonates a specific product."""
    name: str
    server_header: str
    default_page: str
    status_code: int = 200
    extra_headers: dict[str, str] = field(default_factory=dict)
    paths: dict[str, tuple[int, str, str]] = field(default_factory=dict)
    # paths: { "/path": (status_code, content_type, body) }


# ── FortiGate / FortiOS (port 10443 / 443) ────────────────────────
PRODUCT_PROFILES["fortinet"] = ProductProfile(
    name="FortiGate",
    server_header="",
    default_page="""<!DOCTYPE html>
<html>
<head><title></title>
<script>document.location="/remote/login?lang=en";</script>
</head><body></body></html>""",
    status_code=200,
    extra_headers={
        "Set-Cookie": "SVPNCOOKIE=; path=/; secure; httponly;",
        "X-Frame-Options": "SAMEORIGIN",
        "Content-Security-Policy": "frame-ancestors 'self'",
    },
    paths={
        "/remote/login": (200, "text/html", """<!DOCTYPE html><html><head>
<title>FortiGate SSL-VPN</title>
<style>body{font-family:Arial;background:#f5f5f5;margin:0}.login-container{width:400px;margin:100px auto;background:#fff;border-radius:4px;box-shadow:0 2px 8px rgba(0,0,0,.1);padding:40px}.logo{text-align:center;margin-bottom:30px}h2{color:#333;text-align:center}input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:3px;box-sizing:border-box}button{width:100%;padding:12px;background:#d32f2f;color:#fff;border:none;border-radius:3px;cursor:pointer;font-size:14px}button:hover{background:#b71c1c}</style>
</head><body><div class="login-container"><div class="logo"><img src="/resource/images/logo_fw.svg" width="160" alt="FortiGate"></div><h2>SSL-VPN Login</h2><form method="POST" action="/remote/logincheck"><input name="username" placeholder="Username"><input name="credential" type="password" placeholder="Password"><input name="realm" type="hidden" value=""><button type="submit">Login</button></form></div></body></html>"""),
        "/remote/logincheck": (401, "text/html", """<html><body><script>document.location="/remote/login?err=1";</script></body></html>"""),
        "/api/v2/cmdb/system/status": (401, "application/json", '{"http_status":401,"error":"Not Authorized"}'),
    },
)

# ── Palo Alto GlobalProtect (port 443) ────────────────────────────
PRODUCT_PROFILES["paloalto"] = ProductProfile(
    name="GlobalProtect",
    server_header="PanWeb Server/",
    default_page="""<!DOCTYPE html><html><head><title>GlobalProtect Portal</title></head>
<body><h2>GlobalProtect Portal</h2>
<form method="POST" action="/global-protect/login.esp">
<table><tr><td>Username:</td><td><input name="user"></td></tr>
<tr><td>Password:</td><td><input name="passwd" type="password"></td></tr>
<tr><td></td><td><input type="submit" value="Login"></td></tr></table>
</form></body></html>""",
    extra_headers={"X-FRAME-OPTIONS": "DENY"},
    paths={
        "/global-protect/login.esp": (200, "text/html", """<!DOCTYPE html><html><head><title>GlobalProtect Portal</title></head><body><h2>GlobalProtect Portal</h2><form method="POST" action="/global-protect/login.esp"><table><tr><td>Username:</td><td><input name="user"></td></tr><tr><td>Password:</td><td><input name="passwd" type="password"></td></tr><tr><td></td><td><input type="submit" value="Login"></td></tr></table></form></body></html>"""),
        "/ssl-vpn/hipreport.esp": (200, "text/html", "<html><body>OK</body></html>"),
        "/global-protect/portal/css/login.css": (200, "text/css", "body{font-family:Arial}"),
    },
)

# ── Citrix NetScaler / ADC (port 443) ─────────────────────────────
PRODUCT_PROFILES["citrix"] = ProductProfile(
    name="Citrix NetScaler",
    server_header="Citrix Receiver",
    default_page="""<!DOCTYPE html><html><head><title>Citrix Gateway</title>
<meta http-equiv="refresh" content="0;url=/vpn/index.html"></head><body></body></html>""",
    extra_headers={"X-Citrix-Application": "Receiver"},
    paths={
        "/vpn/index.html": (200, "text/html", """<!DOCTYPE html><html><head><title>Citrix Gateway</title><style>body{font-family:'Helvetica Neue',Arial;background:#002b49;color:#fff;margin:0}.container{width:400px;margin:80px auto;text-align:center}h1{font-weight:300}form{background:#fff;color:#333;padding:30px;border-radius:4px;margin-top:20px}input{width:90%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:3px}button{width:90%;padding:12px;background:#0078d4;color:#fff;border:none;border-radius:3px;cursor:pointer}</style></head><body><div class="container"><h1>Citrix Gateway</h1><form method="POST" action="/cgi/login"><input name="login" placeholder="User name"><input name="passwd" type="password" placeholder="Password"><button>Log On</button></form></div></body></html>"""),
        "/cgi/login": (302, "text/html", ""),
    },
)

# ── Ivanti Connect Secure / Pulse Secure (port 443) ───────────────
PRODUCT_PROFILES["ivanti"] = ProductProfile(
    name="Ivanti Connect Secure",
    server_header="Pulse Secure",
    default_page="""<!DOCTYPE html><html><head><title>Welcome</title>
<meta http-equiv="refresh" content="0;url=/dana-na/auth/url_default/welcome.cgi"></head><body></body></html>""",
    paths={
        "/dana-na/auth/url_default/welcome.cgi": (200, "text/html", """<!DOCTYPE html><html><head><title>Ivanti Connect Secure</title><style>body{font-family:Arial;background:#1a1a2e;color:#fff;margin:0}.login{width:380px;margin:80px auto;background:#16213e;padding:30px;border-radius:8px}h2{text-align:center;color:#0f3460}input{width:100%;padding:10px;margin:8px 0;border:1px solid #333;border-radius:4px;background:#0f3460;color:#fff;box-sizing:border-box}button{width:100%;padding:12px;background:#e94560;color:#fff;border:none;border-radius:4px;cursor:pointer}</style></head><body><div class="login"><h2>Sign In</h2><form method="POST" action="/dana-na/auth/url_default/login.cgi"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><input name="realm" type="hidden" value="Users"><button>Sign In</button></form></div></body></html>"""),
    },
)

# ── ManageEngine (port 8443 / 8080) ───────────────────────────────
PRODUCT_PROFILES["manageengine"] = ProductProfile(
    name="ManageEngine",
    server_header="ManageEngine",
    default_page="""<!DOCTYPE html><html><head><title>ManageEngine ServiceDesk Plus</title>
<meta http-equiv="refresh" content="0;url=/WOLogin.do"></head><body></body></html>""",
    paths={
        "/WOLogin.do": (200, "text/html", """<!DOCTYPE html><html><head><title>ManageEngine ServiceDesk Plus :: Login</title><style>body{font-family:Roboto,Arial;background:#f0f2f5;margin:0}.login-box{width:400px;margin:80px auto;background:#fff;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);padding:40px}h1{color:#d32f2f;font-size:20px;text-align:center}input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}button{width:100%;padding:12px;background:#d32f2f;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px}</style></head><body><div class="login-box"><h1>ManageEngine ServiceDesk Plus</h1><form method="POST" action="/j_security_check"><input name="j_username" placeholder="User Name"><input name="j_password" type="password" placeholder="Password"><input name="DOMAIN_NAME" type="hidden" value="AD_AUTH"><button>LOGIN</button></form></div></body></html>"""),
        "/fileupload": (200, "text/html", "<html><body>Upload successful</body></html>"),
        "/api/json/admin": (401, "application/json", '{"response":{"status":"failed","message":"Authentication required"}}'),
    },
)

# ── Jenkins (port 8080) ───────────────────────────────────────────
PRODUCT_PROFILES["jenkins"] = ProductProfile(
    name="Jenkins",
    server_header="Jetty(10.0.13)",
    default_page="""<!DOCTYPE html><html><head><title>Dashboard [Jenkins]</title>
<meta http-equiv="refresh" content="0;url=/login"></head><body></body></html>""",
    extra_headers={"X-Jenkins": "2.426.3", "X-Hudson": "1.395"},
    paths={
        "/login": (200, "text/html", """<!DOCTYPE html><html><head><title>Sign in [Jenkins]</title><style>body{font-family:sans-serif;background:#f0f0f0;margin:0}#page-body{width:400px;margin:60px auto}h1{color:#333;font-size:24px}form{background:#fff;padding:30px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1)}input{width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:3px;box-sizing:border-box}button{padding:10px 20px;background:#4b758b;color:#fff;border:none;border-radius:3px;cursor:pointer}</style></head><body><div id="page-body"><h1>Sign in to Jenkins</h1><form method="POST" action="/j_spring_security_check"><input name="j_username" placeholder="User"><input name="j_password" type="password" placeholder="Password"><button>Sign in</button></form></div></body></html>"""),
        "/api/json": (403, "text/html", "<html><body><h2>HTTP ERROR 403 Forbidden</h2></body></html>"),
    },
)


def get_active_profile() -> ProductProfile | None:
    """Get the product profile from HONEYPOT_PRODUCT env var."""
    product = os.getenv("HONEYPOT_PRODUCT", "").lower().strip()
    if not product:
        return None
    return PRODUCT_PROFILES.get(product)


def list_profiles() -> dict[str, str]:
    """Return available profiles for the UI."""
    return {k: v.name for k, v in PRODUCT_PROFILES.items()}
