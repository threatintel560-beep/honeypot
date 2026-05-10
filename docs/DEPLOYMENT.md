# Deployment guide

## Single-host deployment

```bash
# On a fresh Ubuntu 22.04 VM
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin git make
git clone <your-fork>/honeypot.git && cd honeypot
cp .env.example .env
# edit .env: set HONEY_EXTERNAL_IP, HONEY_DEPLOYMENT_ID
make rotate   # fresh ssh host key
make up
```

## Recommended host firewall (iptables)

```bash
# Accept only the honeypot ports inbound
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 5601 -s <your-admin-ip> -j ACCEPT  # Kibana
iptables -A INPUT -j DROP

# Block outbound from the honeypot network (defense in depth)
iptables -I DOCKER-USER -s 172.18.0.0/16 ! -d 172.18.0.0/16 -j DROP
```

## Port translation (so attackers see :22 and :80)

```bash
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```

## Operations

- **Healthcheck:** `docker compose ps` — all services should be Up.
- **Live feed:** `make tail`
- **Rotate host key weekly:** add `0 3 * * 1 cd /opt/honeypot && make rotate` to root's crontab.
- **Export for IR handoff:** `make export` → `exports/events-<ts>.json`

## Scaling to many sensors

1. Run one instance per public IP. `HONEY_DEPLOYMENT_ID` uniquely identifies each.
2. Point all Filebeat agents at a single centralized Logstash (not the per-host one):
   in `elk/filebeat/filebeat.yml`, change `output.logstash.hosts` to your central collector.
3. Kibana & Elasticsearch run only on the collector; disable them in the remote sensors'
   `docker-compose.yml` by commenting out the `elasticsearch`, `kibana`, and `logstash` services.

## Upgrade

```bash
git pull
make rebuild
```

Events and ES indices are preserved across upgrades.
