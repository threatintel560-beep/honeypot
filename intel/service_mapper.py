"""
Service mapper — determines which honeypot service a CVE should be deployed to.

Maps CVE products/descriptions to the correct honeypot service and port.
This ensures plugins are generated for and deployed to the right service:

  HTTP honeypot (:8080) — web apps, APIs, management consoles
  SSH honeypot (:2222)  — SSH servers, network devices with SSH

The mapping is based on:
  1. Product name keywords
  2. Description keywords (attack vector hints)
  3. CPE vendor/product strings from NVD
"""
from __future__ import annotations

# ── Service definitions ────────────────────────────────────────────
SERVICES = {
    "http": {
        "name": "HTTP Honeypot",
        "port": 8080,
        "public_port": 80,
        "description": "Web applications, APIs, management consoles",
        "container": "hp-http",
    },
    "ssh": {
        "name": "SSH Honeypot",
        "port": 2222,
        "public_port": 22,
        "description": "SSH servers, network device CLI",
        "container": "hp-ssh",
    },
}

# ── Product → service mapping ──────────────────────────────────────
# Products that are clearly SSH-based
_SSH_PRODUCTS = {
    "openssh", "ssh", "dropbear", "libssh", "putty",
    "paramiko", "tectia",
}

# Products that are clearly HTTP/web-based
_HTTP_PRODUCTS = {
    "apache", "nginx", "iis", "tomcat", "php", "wordpress", "drupal",
    "joomla", "confluence", "jira", "gitlab", "jenkins", "spring",
    "struts", "log4j", "exchange", "sharepoint", "weblogic", "websphere",
    "coldfusion", "magento", "prestashop", "moodle", "grafana",
    "kibana", "elasticsearch", "solr", "activemq", "rabbitmq",
    "couchdb", "mongodb", "redis", "memcached", "docker",
    "kubernetes", "rancher", "portainer", "traefik", "haproxy",
    "varnish", "squid", "f5", "citrix", "netscaler", "adc",
    "globalprotect", "pan-os", "fortios", "fortigate", "fortiproxy",
    "pulse", "ivanti", "sonicwall", "zyxel", "draytek",
    "manageengine", "solarwinds", "nagios", "zabbix", "cacti",
    "roundcube", "zimbra", "owa", "outlook", "webmail",
    "phpmyadmin", "adminer", "pgadmin", "wp-admin",
    "fastcgi", "cgi", "php-cgi", "fcgi",
    "api", "rest", "graphql", "soap", "wsdl",
    "vmware", "vcenter", "esxi", "horizon", "workspace",
    "anyconnect", "vpn", "ssl-vpn", "sslvpn",
    "bitbucket", "bamboo", "artifactory", "nexus",
    "spark", "hadoop", "hive", "presto",
    "apisix", "kong", "envoy", "istio",
    "xstream", "jackson", "gson", "fastjson",
}

# Description keywords that indicate HTTP attack vector
_HTTP_KEYWORDS = [
    "http", "web", "url", "path traversal", "directory traversal",
    "sql injection", "xss", "cross-site", "ssrf", "server-side request",
    "remote code execution", "rce", "deserialization", "upload",
    "authentication bypass", "auth bypass", "api", "rest",
    "management interface", "admin panel", "admin console",
    "command injection", "code injection", "template injection",
    "ssti", "jndi", "ldap", "log4j", "ognl", "el injection",
    "file inclusion", "lfi", "rfi", "xxe", "xml",
    "cookie", "session", "header", "request",
    "cgi", "servlet", "jsp", "asp", "php",
    "portal", "dashboard", "console", "webui",
]

# Description keywords that indicate SSH attack vector
_SSH_KEYWORDS = [
    "ssh", "openssh", "sshd", "key exchange", "kex",
    "authentication", "brute force", "password",
    "shell", "terminal", "cli", "command line",
    "telnet", "rsh", "rlogin",
]


def detect_service(cve: dict) -> str:
    """
    Determine which honeypot service a CVE should target.

    Args:
        cve: dict with keys: product, vendor, description

    Returns:
        "http" or "ssh"
    """
    product = (cve.get("product") or "").lower()
    vendor = (cve.get("vendor") or "").lower()
    description = (cve.get("description") or "").lower()

    # Check explicit SSH products
    for ssh_prod in _SSH_PRODUCTS:
        if ssh_prod in product or ssh_prod in vendor:
            return "ssh"

    # Check explicit HTTP products
    for http_prod in _HTTP_PRODUCTS:
        if http_prod in product or http_prod in vendor:
            return "http"

    # Fall back to description keyword analysis
    ssh_score = sum(1 for kw in _SSH_KEYWORDS if kw in description)
    http_score = sum(1 for kw in _HTTP_KEYWORDS if kw in description)

    if ssh_score > http_score and ssh_score >= 2:
        return "ssh"

    # Default to HTTP — most CVEs are web-based
    return "http"


def get_service_info(service: str) -> dict:
    """Get service metadata (port, name, etc.)."""
    return SERVICES.get(service, SERVICES["http"])


def get_port_for_service(service: str) -> int:
    """Get the internal port for a service."""
    return SERVICES.get(service, SERVICES["http"])["port"]


def get_public_port_for_service(service: str) -> int:
    """Get the public-facing port for a service."""
    return SERVICES.get(service, SERVICES["http"])["public_port"]
