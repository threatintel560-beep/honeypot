# HoneyForge — Modular High-Interaction Honeypot Framework

> A dockerized, pluggable honeypot platform built for threat intelligence teams.
> Drop in new CVEs as plugins. Ship every session to ELK. Stay off Censys fingerprints.

---

## Features

- **High-interaction by default** — real SSH shell (paramiko), stateful HTTP, session recording.
- **Modular CVE plugins** — add a new exploit in one file. Hot-reloadable in dev.
- **Anti-detection hardening** — randomized banners, jittered timings, rotating host keys, no default strings that match Censys honeypot signatures.
- **ELK pipeline** — Elasticsearch + Logstash + Kibana + Filebeat, with pre-parsed attacker events.
- **One-command deploy** — `make up` and you're live.
- **Safe by design** — all sessions run in disposable containers with no-egress network policies by default.

---

## Quick Start

```bash
git clone <your-fork>/honeypot.git && cd honeypot
cp .env.example .env
# edit .env to set HONEY_EXTERNAL_IP and any other overrides
make up
```

Kibana: `http://<host>:5601`
SSH honeypot: `<host>:2222`
HTTP honeypot: `<host>:8080`

---

## Architecture

```
                       internet attackers
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
         ssh:2222        http:8080        (future: smb, rdp, redis…)
              │               │                │
              └────── JSON event stream ───────┘
                              │
                         filebeat
                              │
                          logstash ──► elasticsearch ──► kibana
```

Every service imports the shared `honeycore` library, so logging format, session IDs, and
anti-detection helpers are uniform across honeypots.

---

## Adding a New CVE

```bash
python scripts/add_cve_plugin.py CVE-2024-12345 --service http
# edit the generated file under services/http/plugins/
make reload-http
```

See [`docs/ADDING_CVE.md`](docs/ADDING_CVE.md) for the full plugin contract.

---

## Operator Playbook

| Goal | Command |
|---|---|
| Start everything | `make up` |
| Stop everything | `make down` |
| Tail live attacker events | `make tail` |
| Rotate SSH host keys & banners | `make rotate` |
| Rebuild after code change | `make rebuild` |
| Export last 24h of events | `make export` |

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system design
- [`docs/ADDING_CVE.md`](docs/ADDING_CVE.md) — CVE plugin authoring guide
- [`docs/ANTI_DETECTION.md`](docs/ANTI_DETECTION.md) — staying off Censys / Shodan honeypot tags

---

## Legal & Safety

This project is for **defensive threat intelligence research only**. Deploy only on
infrastructure you own or are explicitly authorized to instrument. The authors accept no
liability for misuse.
