# HoneyForge — Distributed Architecture & Security Report

## Executive Summary

HoneyForge operates as a distributed threat intelligence platform with a **central command server** and multiple **remote honeypot sensors** deployed across diverse networks. This document defines the architecture, security controls, data flows, and operational procedures for production deployment.

**Design principles:**
- Remote sensors are stateless, disposable, and minimal-attack-surface
- All inter-node communication is encrypted and mutually authenticated
- No secrets or intelligence data reside on sensors
- Central server is never internet-facing
- Defense-in-depth at every layer

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CENTRAL COMMAND SERVER                               │
│                    (Private network / VPN-only access)                       │
│                                                                             │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐  │
│  │  Intel Module │  │ Elasticsearch │  │    Kibana     │  │   Ollama    │  │
│  │  :8090       │  │  :9200        │  │  :5601        │  │  :11434     │  │
│  │              │  │               │  │               │  │  (LLM)      │  │
│  │ • CVE Watch  │  │ • All events  │  │ • Dashboards  │  │             │  │
│  │ • Plugin Gen │  │ • All sensors │  │ • Queries     │  │             │  │
│  │ • IOC Extract│  │ • Retention   │  │               │  │             │  │
│  │ • TAXII 2.1  │  │               │  │               │  │             │  │
│  │ • Web UI     │  │               │  │               │  │             │  │
│  └───────────────┘  └───────────────┘  └───────────────┘  └─────────────┘  │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Logstash (:5044) — ONLY port exposed to sensors (TLS + mTLS)        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  Firewall rules:                                                            │
│    INBOUND:  :5044 from sensor IPs only (mTLS)                             │
│    INBOUND:  :8090, :5601 from operator VPN only                           │
│    OUTBOUND: :443 to CISA, NVD, Ollama (localhost), MISP/OpenCTI           │
│    DEFAULT:  DROP all                                                       │
└─────────────────────────────────────────────────────────────────────────────┘
          ▲ mTLS (:5044)        ▲ mTLS (:5044)        ▲ mTLS (:5044)
          │                     │                     │
┌─────────┴──────────┐ ┌───────┴────────────┐ ┌──────┴─────────────┐
│  SENSOR: forti-01  │ │  SENSOR: web-01    │ │  SENSOR: vpn-01    │
│  Provider: DO      │ │  Provider: Vultr   │ │  Provider: Hetzner │
│  Region: US-East   │ │  Region: EU-West   │ │  Region: APAC      │
│                    │ │                    │ │                    │
│  :443 → FortiGate │ │  :80 → Apache      │ │  :443 → Citrix    │
│  :22  → SSH pot   │ │  :22 → SSH pot     │ │  :4443 → PaloAlto │
│                    │ │  :8080 → Jenkins   │ │                    │
│  Filebeat → TLS ───┼─┼────────────────────┼─┼──→ Central :5044  │
│                    │ │                    │ │                    │
│  NO management UI  │ │  NO management UI  │ │  NO management UI  │
│  NO database       │ │  NO database       │ │  NO database       │
│  NO secrets        │ │  NO secrets        │ │  NO secrets        │
└────────────────────┘ └────────────────────┘ └────────────────────┘
```

---

## 2. Component Responsibilities

### 2.1 Central Command Server

| Component | Role | Security Posture |
|---|---|---|
| Intel Module | CVE research, plugin generation, IOC extraction, STIX/TAXII | Internal only, VPN access |
| Elasticsearch | Event storage from all sensors | No public exposure, auth enabled |
| Logstash | Receives logs from remote sensors | Only port exposed to sensors, mTLS |
| Kibana | Visualization and analysis | Internal only, VPN access |
| Ollama | Local LLM for plugin generation | Localhost only, no network exposure |

### 2.2 Remote Sensor (Minimal)

| Component | Role | Security Posture |
|---|---|---|
| HTTP Honeypot | Captures web exploits | Public-facing (that's the point) |
| SSH Honeypot | Captures brute-force + shell commands | Public-facing |
| Product Profiles | Spoofs specific products (FortiGate, etc.) | Public-facing |
| CVE Plugins | Detects and logs specific exploits | Loaded from disk, read-only |
| Filebeat | Ships JSON logs to central Logstash | Outbound only to central, mTLS |

**What is NOT on sensors:**
- No Elasticsearch, Kibana, or Logstash
- No Intel UI or web management
- No LLM or AI components
- No SQLite database
- No API keys or credentials (except Filebeat TLS cert)
- No TAXII server

---

## 3. Security Controls

### 3.1 Network Security

#### Central Server
```
# iptables rules (central)
-A INPUT -p tcp --dport 5044 -s <sensor1_ip> -j ACCEPT
-A INPUT -p tcp --dport 5044 -s <sensor2_ip> -j ACCEPT
-A INPUT -p tcp --dport 5044 -s <sensor3_ip> -j ACCEPT
-A INPUT -p tcp --dport 8090 -s <vpn_subnet> -j ACCEPT
-A INPUT -p tcp --dport 5601 -s <vpn_subnet> -j ACCEPT
-A INPUT -p tcp --dport 22   -s <vpn_subnet> -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -j DROP

-A OUTPUT -p tcp --dport 443 -j ACCEPT   # CISA, NVD, MISP
-A OUTPUT -p tcp --dport 53  -j ACCEPT   # DNS
-A OUTPUT -p udp --dport 53  -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -j DROP
```

#### Remote Sensors
```
# iptables rules (sensor) — CRITICAL: block all egress except log shipping
-A INPUT -p tcp --dport 22   -j ACCEPT   # Honeypot SSH (public)
-A INPUT -p tcp --dport 80   -j ACCEPT   # Honeypot HTTP (public)
-A INPUT -p tcp --dport 443  -j ACCEPT   # Honeypot HTTPS (public)
-A INPUT -p tcp --dport 10443 -j ACCEPT  # FortiGate (public)
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -j DROP

# EGRESS: ONLY allow log shipping to central
-A OUTPUT -p tcp -d <central_ip> --dport 5044 -j ACCEPT
-A OUTPUT -p tcp --dport 53  -j ACCEPT   # DNS (for TLS cert validation)
-A OUTPUT -p udp --dport 53  -j ACCEPT
-A OUTPUT -p udp --dport 123 -j ACCEPT   # NTP
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -j LOG --log-prefix "EGRESS_BLOCKED: "
-A OUTPUT -j DROP
```

**Why egress blocking is critical:** If an attacker achieves code execution inside the honeypot container, they cannot:
- Pivot to other systems
- Download additional tools
- Exfiltrate data
- Establish C2 channels

### 3.2 Transport Security (Filebeat → Logstash)

**Mutual TLS (mTLS)** — both sides authenticate:

```yaml
# Filebeat config on sensor
output.logstash:
  hosts: ["central.example.com:5044"]
  ssl.certificate_authorities: ["/etc/filebeat/ca.pem"]
  ssl.certificate: "/etc/filebeat/sensor-forti-01.crt"
  ssl.key: "/etc/filebeat/sensor-forti-01.key"
  ssl.verification_mode: full
```

```yaml
# Logstash input on central
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate_authorities => ["/etc/logstash/ca.pem"]
    ssl_certificate => "/etc/logstash/logstash.crt"
    ssl_key => "/etc/logstash/logstash.key"
    ssl_verify_mode => "force_peer"  # Require client cert
  }
}
```

**Certificate management:**
- Self-signed CA (generated per deployment)
- Each sensor gets a unique client certificate
- Certificates rotated every 90 days
- Revocation: remove sensor cert from CA trust → immediate disconnect

### 3.3 Container Security (Sensors)

```yaml
# docker-compose.sensor.yml security settings
services:
  honeypot:
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:size=10M
      - /var/log/honeypot:size=100M
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'
    networks:
      honeynet:
        # No inter-container communication needed
    dns: []  # No DNS resolution from honeypot containers
```

**Additional hardening:**
- Containers run as UID 1500 (non-root)
- Filesystem is read-only (logs go to tmpfs, shipped by Filebeat)
- Memory limited to 256MB (prevents resource exhaustion attacks)
- CPU limited to 0.5 cores
- No capabilities granted
- No new privileges can be gained

### 3.4 Host Security (Sensors)

```bash
# Minimal OS (Ubuntu Server 22.04 minimal)
# Only installed packages: docker, ufw, unattended-upgrades

# Auto-updates enabled
apt install unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# SSH hardened (for operator access only from VPN)
# /etc/ssh/sshd_config
Port 2200                    # Non-standard port for operator SSH
PermitRootLogin no
PasswordAuthentication no
AllowUsers deploy
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2

# Fail2ban for operator SSH
apt install fail2ban
```

### 3.5 Secrets Management

| Secret | Where stored | Who has access |
|---|---|---|
| Filebeat TLS cert/key | Sensor: `/etc/filebeat/` (600 perms) | Filebeat process only |
| CA certificate | Central: `/etc/logstash/ca.pem` | Logstash process |
| Elasticsearch password | Central: `.env` file (600 perms) | Docker compose only |
| TAXII API key | Central: Intel DB | Intel module only |
| LLM API key (if OpenAI) | Central: Intel DB | Intel module only |
| Operator SSH keys | Central + Sensors: `~/.ssh/authorized_keys` | Operators only |

**No secrets on sensors except the Filebeat TLS client certificate.**

---

## 4. Data Flow

### 4.1 Attack Capture Flow

```
1. Attacker → Sensor :443 (thinks it's FortiGate)
2. Honeypot container processes request
3. CVE plugin matches → logs cve_exploit_attempt event
4. Event written to /var/log/honeypot/http.json (tmpfs)
5. Filebeat reads log line
6. Filebeat ships to Central Logstash over mTLS
7. Logstash enriches (GeoIP, tagging)
8. Logstash writes to Elasticsearch
9. Intel IOC Extractor reads from ES (every 10 min)
10. IOCs persisted to Intel DB
11. STIX bundle auto-published on TAXII endpoint
12. MISP/OpenCTI polls TAXII and ingests
```

### 4.2 Plugin Deployment Flow

```
1. Central: CVE Watcher discovers new KEV CVE
2. Central: LLM generates honeypot plugin
3. Central: Operator reviews in Intel UI
4. Central: Clicks "Deploy"
5. Central: Plugin written to /app/generated_plugins
6. Central: Sync script pushes to sensors:
     rsync -e "ssh -p 2200" plugins/ deploy@sensor1:/opt/honeypot/plugins/
7. Sensor: Operator triggers reload:
     ssh -p 2200 deploy@sensor1 "docker restart hp-http"
8. Sensor: Honeypot loads new plugin, starts catching exploits
```

### 4.3 Sensor Provisioning Flow

```
1. Spin up cheapest VPS ($3-5/mo) on new provider
2. Run provisioning script (automated):
   - Install Docker
   - Configure firewall (block all egress except central)
   - Deploy Filebeat with TLS cert
   - Deploy honeypot containers
   - Set unique HONEY_DEPLOYMENT_ID
3. Add sensor IP to central Logstash allowlist
4. Verify log shipping: check Kibana for events from new sensor
5. Push CVE plugins to new sensor
6. Done — sensor is live in ~5 minutes
```

---

## 5. Threat Model

### 5.1 Threats to Remote Sensors

| Threat | Mitigation |
|---|---|
| Attacker achieves RCE inside honeypot container | Egress blocked, read-only FS, no capabilities, memory limited. Container is disposable. |
| Attacker escapes container to host | `no-new-privileges`, `cap_drop: ALL`, minimal kernel surface. Host has no valuable data. |
| Attacker discovers it's a honeypot | Anti-detection measures (deception engine, jitter, realistic banners). If flagged, destroy and redeploy on new IP. |
| Attacker DoS the sensor | Resource limits on containers. Sensor is cheap — spin up another. |
| Attacker intercepts log traffic | mTLS encryption. Even if intercepted, attacker only sees their own attack data. |
| Attacker compromises host OS | Auto-updates, minimal packages, no root SSH. Destroy and redeploy. |
| Sensor cert stolen | Revoke cert on central CA. Sensor can no longer ship logs. Redeploy with new cert. |

### 5.2 Threats to Central Server

| Threat | Mitigation |
|---|---|
| Attacker finds central server IP | Never exposed to internet. Only reachable via VPN + sensor IPs on :5044. |
| Compromised sensor attacks central | Logstash only accepts Beats protocol on :5044. No shell access. Firewall blocks all other ports from sensor IPs. |
| Malicious log data injection | Logstash validates JSON schema. Elasticsearch has field type mappings. IOC extractor uses regex, not eval. |
| LLM prompt injection via CVE data | Plugin generator validates AST before saving. Generated code is never auto-executed on central. |
| Operator account compromise | MFA on VPN. SSH key-only auth. Audit logging on all admin actions. |
| Data exfiltration from ES | ES not exposed to internet. VPN-only access. Encryption at rest optional. |

### 5.3 Threats to Intelligence Output

| Threat | Mitigation |
|---|---|
| Attacker poisons IOC data | IOCs are extracted from real attack traffic. Deduplication and hit-count thresholds filter noise. |
| False positives in STIX output | Human review of high-value indicators. Confidence scoring based on hit count and sensor diversity. |
| TAXII endpoint abused | API key authentication. Rate limiting. Only serves read-only data. |

---

## 6. Operational Procedures

### 6.1 Daily Operations (Automated)

- CVE Watcher polls CISA KEV + NVD (every 6h)
- IOC Extractor processes events (every 10 min)
- STIX bundles auto-published on TAXII
- Filebeat ships logs continuously
- Auto-pipeline generates + deploys plugins for KEV CVEs

### 6.2 Weekly Operations (Operator)

- Review new CVEs in Intel UI
- Review and approve plugin drafts
- Check sensor health (Kibana → unique source IPs per sensor)
- Rotate any sensors that show signs of being flagged

### 6.3 Monthly Operations (Operator)

- Rotate Filebeat TLS certificates
- Update banner pools in deception engine
- Review and prune old IOCs
- Update watched product list based on threat landscape
- Patch sensor host OS (auto-updates handle most)

### 6.4 Incident Response: Sensor Compromise

```
1. Revoke sensor's Filebeat TLS certificate on central
2. Destroy the VPS (provider console → delete)
3. Provision new sensor on different IP/provider
4. Issue new TLS certificate
5. Push plugins to new sensor
6. Update central firewall with new sensor IP
7. Total time: ~10 minutes
```

---

## 7. Deployment Specifications

### 7.1 Central Server Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 2 cores | 4 cores |
| RAM | 4 GB | 8 GB |
| Disk | 50 GB SSD | 100 GB SSD |
| Network | 100 Mbps | 1 Gbps |
| OS | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |

### 7.2 Remote Sensor Requirements

| Resource | Minimum | Notes |
|---|---|---|
| CPU | 1 vCPU | Shared OK |
| RAM | 512 MB | 256MB for honeypot + 256MB for Filebeat |
| Disk | 10 GB | Logs are tmpfs, shipped immediately |
| Network | 100 Mbps | Bandwidth for log shipping is minimal |
| OS | Ubuntu 22.04 minimal | Smallest possible attack surface |
| Cost | $3-5/month | Cheapest VPS tier on any provider |

### 7.3 Network Requirements

| Path | Protocol | Port | Auth |
|---|---|---|---|
| Sensor → Central | Beats/TLS | 5044 | mTLS (client cert) |
| Operator → Central | SSH | 22 | Key-only via VPN |
| Operator → Central | HTTPS | 8090 | VPN only |
| Central → Internet | HTTPS | 443 | For CVE feeds |
| Sensor → Internet | BLOCKED | — | Egress denied |
| Internet → Sensor | TCP | 22,80,443,etc. | Honeypot ports (public) |

---

## 8. Files to Create for Distributed Mode

```
honeypot/
├── deploy/
│   ├── central/
│   │   ├── docker-compose.central.yml    # ES, Logstash, Kibana, Intel
│   │   ├── logstash-tls.conf            # mTLS input config
│   │   ├── generate-ca.sh              # Create CA + certs
│   │   └── firewall-central.sh         # iptables rules
│   ├── sensor/
│   │   ├── docker-compose.sensor.yml    # Honeypot + Filebeat only
│   │   ├── filebeat-remote.yml         # Ships to central over TLS
│   │   ├── firewall-sensor.sh         # Block egress
│   │   └── provision.sh              # One-command sensor setup
│   └── certs/
│       ├── ca.pem                     # CA certificate
│       ├── ca-key.pem                 # CA private key (central only)
│       └── README.md                  # Cert rotation instructions
```

---

## 9. Cost Analysis

### Minimal Deployment (3 sensors)

| Item | Monthly Cost |
|---|---|
| Central server (existing Mac or $20 VPS) | $0-20 |
| Sensor 1 (DigitalOcean $4 droplet) | $4 |
| Sensor 2 (Vultr $3.50) | $3.50 |
| Sensor 3 (Hetzner €3.29) | $3.50 |
| **Total** | **$11-31/month** |

### Production Deployment (10 sensors)

| Item | Monthly Cost |
|---|---|
| Central server (dedicated, 8GB RAM) | $40 |
| 10 sensors across 5 providers | $40 |
| Domain + TLS certs (Let's Encrypt) | $0 |
| **Total** | **~$80/month** |

---

## 10. Summary

This architecture ensures:

1. **Sensors are disposable** — no data loss if compromised, redeploy in minutes
2. **Central is invisible** — never internet-facing, VPN-only access
3. **Communication is encrypted** — mTLS between all nodes
4. **Egress is blocked** — compromised sensors cannot pivot or exfiltrate
5. **Intelligence flows one way** — sensors → central → TAXII consumers
6. **Plugins flow one way** — central → sensors (operator-initiated)
7. **No single point of failure** — lose a sensor, others keep collecting
8. **Scalable** — add sensors in 5 minutes, $3-5/month each
9. **Diverse** — sensors across providers/regions avoid correlated detection
10. **Auditable** — all events timestamped, all actions logged

The system produces continuous, automated threat intelligence from real attack traffic with minimal operator intervention and maximum security posture.
