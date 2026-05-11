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
        "/remote/login": (200, "text/html", """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FortiGate SSL-VPN</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5;min-height:100vh;display:flex;align-items:center;justify-content:center}
.login-wrap{width:100%;max-width:420px;padding:20px}
.login-box{background:#fff;border-radius:4px;box-shadow:0 2px 12px rgba(0,0,0,.08);padding:48px 40px;text-align:center}
.logo{margin-bottom:8px}
.logo svg{width:140px;height:auto}
.brand{font-size:13px;color:#666;margin-bottom:24px;letter-spacing:.5px}
h2{font-size:18px;font-weight:500;color:#333;margin-bottom:28px}
.form-group{margin-bottom:16px;text-align:left}
.form-group input{width:100%;padding:11px 14px;border:1px solid #d0d0d0;border-radius:3px;font-size:14px;color:#333;outline:none;transition:border .2s}
.form-group input:focus{border-color:#c00}
.form-group input::placeholder{color:#999}
.btn-login{width:100%;padding:12px;background:#c00;color:#fff;border:none;border-radius:3px;font-size:14px;font-weight:500;cursor:pointer;margin-top:8px;transition:background .2s}
.btn-login:hover{background:#a00}
.footer{margin-top:20px;font-size:11px;color:#999}
</style></head>
<body><div class="login-wrap"><div class="login-box">
<div class="logo"><svg viewBox="0 0 200 40" xmlns="http://www.w3.org/2000/svg"><text x="10" y="30" font-family="Arial,sans-serif" font-size="28" font-weight="bold" fill="#c00">FORTI</text><text x="90" y="30" font-family="Arial,sans-serif" font-size="28" font-weight="bold" fill="#333">GATE</text></svg></div>
<div class="brand">Security Fabric</div>
<h2>SSL-VPN Login</h2>
<form method="POST" action="/remote/logincheck">
<div class="form-group"><input name="username" placeholder="Username" autocomplete="off"></div>
<div class="form-group"><input name="credential" type="password" placeholder="Password"></div>
<input name="realm" type="hidden" value="">
<button type="submit" class="btn-login">Login</button>
</form>
<div class="footer">FortiOS 7.4</div>
</div></div></body></html>"""),
        "/remote/logincheck": (401, "text/html", """<html><body><script>document.location="/remote/login?err=1&lang=en";</script></body></html>"""),
        "/api/v2/cmdb/system/status": (401, "application/json", '{"http_status":401,"revision":"","serial":"FGT60F0000000000","version":"v7.4.4","build":2573}'),
        "/resource/images/logo_fw.svg": (200, "image/svg+xml", '<svg viewBox="0 0 200 40" xmlns="http://www.w3.org/2000/svg"><text x="10" y="30" font-family="Arial,sans-serif" font-size="28" font-weight="bold" fill="#c00">FORTI</text><text x="90" y="30" font-family="Arial,sans-serif" font-size="28" font-weight="bold" fill="#333">GATE</text></svg>'),
    },
)

# ── Palo Alto GlobalProtect (port 443) ────────────────────────────
PRODUCT_PROFILES["paloalto"] = ProductProfile(
    name="GlobalProtect",
    server_header="PanWeb Server/",
    default_page="""<!DOCTYPE html><html><head><title>GlobalProtect Portal</title>
<meta http-equiv="refresh" content="0;url=/global-protect/login.esp"></head><body></body></html>""",
    extra_headers={"X-FRAME-OPTIONS": "DENY"},
    paths={
        "/global-protect/login.esp": (200, "text/html", """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GlobalProtect Portal</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#1a237e 0%,#0d47a1 50%,#01579b 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}
.login-card{background:#fff;border-radius:8px;box-shadow:0 8px 40px rgba(0,0,0,.3);padding:48px 40px;width:380px;text-align:center}
.logo{margin-bottom:24px}
.logo svg{width:180px}
h1{font-size:16px;color:#333;font-weight:500;margin-bottom:32px}
.form-group{margin-bottom:16px;text-align:left}
.form-group label{display:block;font-size:12px;color:#666;margin-bottom:4px;font-weight:500}
.form-group input{width:100%;padding:10px 12px;border:1px solid #ccc;border-radius:4px;font-size:14px;outline:none;transition:border .2s}
.form-group input:focus{border-color:#1565c0}
.btn{width:100%;padding:12px;background:#1565c0;color:#fff;border:none;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer;margin-top:12px}
.btn:hover{background:#0d47a1}
.footer{margin-top:24px;font-size:11px;color:#999}
</style></head>
<body><div class="login-card">
<div class="logo"><svg viewBox="0 0 200 32" xmlns="http://www.w3.org/2000/svg"><text x="0" y="26" font-family="Arial,sans-serif" font-size="22" font-weight="bold" fill="#1565c0">PALO ALTO</text><text x="0" y="26" font-family="Arial,sans-serif" font-size="22" font-weight="bold" fill="#333" dx="148">|</text></svg></div>
<h1>GlobalProtect Portal</h1>
<form method="POST" action="/global-protect/login.esp">
<div class="form-group"><label>Username</label><input name="user" autocomplete="off"></div>
<div class="form-group"><label>Password</label><input name="passwd" type="password"></div>
<button type="submit" class="btn">Sign In</button>
</form>
<div class="footer">Palo Alto Networks &copy; 2024</div>
</div></body></html>"""),
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
        "/vpn/index.html": (200, "text/html", """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Citrix Gateway</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#002b49;min-height:100vh;display:flex;align-items:center;justify-content:center}
.login-card{background:#fff;border-radius:8px;box-shadow:0 8px 40px rgba(0,0,0,.4);padding:48px 40px;width:400px}
.header{text-align:center;margin-bottom:32px}
.header svg{width:160px;margin-bottom:12px}
.header h1{font-size:18px;color:#002b49;font-weight:400}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:13px;color:#555;margin-bottom:6px}
.form-group input{width:100%;padding:11px 14px;border:1px solid #ccc;border-radius:4px;font-size:14px;outline:none}
.form-group input:focus{border-color:#002b49;box-shadow:0 0 0 2px rgba(0,43,73,.1)}
.btn{width:100%;padding:12px;background:#002b49;color:#fff;border:none;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer;margin-top:8px}
.btn:hover{background:#003d66}
.footer{text-align:center;margin-top:20px;font-size:11px;color:#999}
</style></head>
<body><div class="login-card">
<div class="header">
<svg viewBox="0 0 160 28" xmlns="http://www.w3.org/2000/svg"><text x="0" y="22" font-family="Arial,sans-serif" font-size="20" font-weight="bold" fill="#002b49">Citrix</text><text x="62" y="22" font-family="Arial,sans-serif" font-size="20" fill="#666"> Gateway</text></svg>
<h1>Log On</h1>
</div>
<form method="POST" action="/cgi/login">
<div class="form-group"><label>User name:</label><input name="login" autocomplete="off"></div>
<div class="form-group"><label>Password:</label><input name="passwd" type="password"></div>
<button type="submit" class="btn">Log On</button>
</form>
<div class="footer">&copy; Citrix Systems, Inc.</div>
</div></body></html>"""),
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
