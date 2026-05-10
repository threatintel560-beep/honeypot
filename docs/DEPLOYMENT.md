# Production Deployment Guide

## Quick Start

```bash
# Clone and deploy
git clone <repo-url> && cd honeypot
./scripts/deploy_prod.sh --external-ip YOUR_PUBLIC_IP
```

This handles everything: key generation, port forwarding, firewall, Docker build, and health checks.

---

## Architecture in Production

```
Internet (Censys, Shodan, real attackers)
    │
    ├── :22  ──→ NAT ──→ :2222 (SSH honeypot)
    ├── :80  ──→ NAT ──→ :8080 (HTTP honeypot + CVE plugins)
    │
    │   [internal only]
    ├── :8090 ──→ Intel UI + TAXII 2.1 server
    ├── :5601 ──→ Kibana dashboards
    └── :9200 ──→ Elasticsearch
```

## The Live Intelligence Loop

Once deployed and exposed to the internet, the system runs autonomously:

```
┌─────────────────────────────────────────────────────────────────┐
│                    AUTO-PIPELINE (every 12h)                     │
│                                                                 │
│  1. CVE Watcher polls CISA KEV + NVD                           │
│     └─ Finds new critical CVEs matching watched products        │
│                                                                 │
│  2. Plugin Generator creates honeypot emulators                 │
│     └─ Uses LLM (Ollama/OpenAI) or template fallback           │
│                                                                 │
│  3. Auto-Deploy writes plugin to HTTP honeypot                  │
│     └─ Hot-reload picks up new CVE emulation                    │
│                                                                 │
│  4. Attackers & scanners hit the honeypot                       │
│     └─ Censys/Shodan see realistic service                      │
│     └─ Exploit attempts get captured with full payload          │
│                                                                 │
│  5. IOC Extractor processes attack events (every 10 min)        │
│     └─ IPs, URLs, domains, hashes extracted and deduplicated    │
│                                                                 │
│  6. STIX bundles auto-published on TAXII endpoint               │
│     └─ MISP/OpenCTI/TheHive poll and ingest                    │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

### Auto-deploy modes

Set in Intel UI → Config, or in `.env`:

| Mode | Behavior |
|---|---|
| `manual` | Plugins stay as drafts. Operator reviews and deploys manually. |
| `auto_kev` | Auto-deploy plugins for CISA KEV CVEs (actively exploited in the wild). Recommended. |
| `auto_all` | Auto-deploy all generated plugins. Aggressive — more coverage, less review. |

### TAXII 2.1 endpoint

The TAXII server runs at `http://<intel-host>:8090/taxii2/`.

**Collections:**

| Collection ID | Content |
|---|---|
| `honeyforge-all-intel` | Full STIX: vulnerabilities, attack patterns, indicators, sightings, infrastructure |
| `honeyforge-iocs` | IOCs only (IPs, URLs, domains, hashes) |
| `honeyforge-cve-intel` | CVE intelligence with ATT&CK mappings |

**Authentication:** Set `TAXII_API_KEY` in config. Consumers pass it via `X-TAXII-Key` header.

**Connect MISP:**
```
Server URL: http://<intel-host>:8090/taxii2/
Collection: honeyforge-all-intel
Auth header: X-TAXII-Key: <your-key>
Pull frequency: every 15 minutes
```

**Connect OpenCTI:**
```yaml
# opencti connector config
connector:
  type: EXTERNAL_IMPORT
  name: HoneyForge
  scope: taxii2
  uri: http://<intel-host>:8090/taxii2/collections/honeyforge-all-intel/objects/
  interval: 900  # 15 min
```

### LLM Backend

For AI-powered plugin generation:

```bash
# On the host machine (not in Docker)
brew install ollama
ollama serve &
ollama pull qwen2.5-coder:14b
```

Then in Intel UI → Config:
- Mode: `ollama`
- Model: `qwen2.5-coder:14b`
- Host: `http://host.docker.internal:11434`

### Scanner handling

The HTTP honeypot detects Censys, Shodan, GreyNoise, and other scanners by:
- User-Agent pattern matching
- Known scanner IP prefix matching

Scanner probes are:
- Served pixel-perfect responses matching real Apache/nginx/IIS
- Logged as `recon_scan` events (separate from exploit attempts)
- Never shown honeypot indicators

This means scanners index your honeypot as a real service, attracting real attackers.

---

## Security Checklist

- [ ] Fresh SSH host key generated (`make rotate`)
- [ ] Unique `HONEY_DEPLOYMENT_ID` per host
- [ ] Port 22→2222 and 80→8080 via NAT (attackers see standard ports)
- [ ] Egress blocked from honeypot containers
- [ ] No rDNS containing "honey", "research", "security" on the IP
- [ ] Intel UI (8090) and Kibana (5601) NOT exposed to internet
- [ ] `TAXII_API_KEY` set if TAXII endpoint is network-accessible
- [ ] `DECEPTION_STRICT=true` in .env

---

## Monitoring

**Signs the honeypot is working:**
- Unique source IPs increasing daily
- `cve_exploit_attempt` events appearing in Kibana
- IOC count growing on the Intel dashboard
- STIX bundles being pulled by TAXII consumers

**Signs you've been flagged:**
- Sudden drop in unique source IPs
- Only scanner traffic, no exploit attempts
- Bots connecting and immediately disconnecting

**Recovery if flagged:**
- `make rotate` (new SSH key + restart)
- Change the external IP if possible
- Update banner pool in `honeycore/deception.py`

---

## Useful commands

```bash
make up              # Start all services
make down            # Stop all services
make rebuild         # Full rebuild
make logs            # Follow all logs
make tail            # Follow honeypot logs only
make rotate          # New SSH key + restart honeypots
make reload-http     # Reload HTTP honeypot (picks up new plugins)
make reload-intel    # Restart intel module
make deploy          # Full production deployment
make demo            # Run demo (no Docker needed)
make demo-all        # Demo all CVEs
```
