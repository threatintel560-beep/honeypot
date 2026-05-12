# HoneyForge Setup Guide — Central + Remote Sensor

## Prerequisites

- Mac with Docker Desktop installed
- Oracle Cloud free VPS (Ubuntu 22.04, 1GB RAM)
- ngrok account (free tier)
- SSH key pair (`~/.ssh/id_ed25519`)

---

## Part 1: Central Controller (Your Mac)

### Step 1: Start Docker Desktop

```bash
open -a Docker
# Wait for whale icon in menu bar (~30s)
```

### Step 2: Start HoneyForge services

```bash
cd ~/github/honeypot
make up
```

Wait ~60 seconds for Elasticsearch to be healthy.

### Step 3: Rebuild Intel container (if code changed)

```bash
docker compose build --no-cache intel && docker compose up -d intel
```

### Step 4: Start ngrok to expose Intel module

```bash
make expose-intel
```

**Note the ngrok URL** — e.g. `https://abc123.ngrok-free.app`  
This is what the remote sensor will connect to.

### Step 5: Verify Intel UI is accessible

```bash
open http://localhost:8090
```

### Step 6: (Optional) Start Ollama for AI plugin generation

```bash
ollama serve &
```

---

## Part 2: Remote Sensor (Oracle Cloud VPS)

### Step 7: Copy project to VPS

From your Mac terminal:

```bash
rsync -avz --exclude='.venv' --exclude='__pycache__' --exclude='logs' --exclude='exports' --exclude='.git' \
  /Users/seru/github/honeypot/ ubuntu@<VPS-IP>:/opt/honeyforge/
```

Replace `<VPS-IP>` with your Oracle VPS public IP.

### Step 8: SSH into VPS

```bash
ssh ubuntu@<VPS-IP>
```

### Step 9: Run provisioning script

```bash
cd /opt/honeyforge
sudo bash deploy/sensor/provision.sh
```

This will:
- Install Docker + firewall + fail2ban
- Move operator SSH to port 2200
- Open honeypot ports (22, 80, 443, 10443, 4443, 8443)
- Configure .env with unique sensor ID
- Start all honeypot containers
- Enable auto security updates

### Step 10: Start the event shipper

```bash
python3 /opt/honeyforge/deploy/sensor/ship_events.py \
  --central-url https://abc123.ngrok-free.app \
  --sensor-key "" \
  --sensor-id hp-oracle-01 \
  --log-dir /opt/honeyforge/logs
```

Replace `https://abc123.ngrok-free.app` with your actual ngrok URL from Step 4.

To run it in the background:

```bash
nohup python3 /opt/honeyforge/deploy/sensor/ship_events.py \
  --central-url https://abc123.ngrok-free.app \
  --sensor-key "" \
  --sensor-id hp-oracle-01 \
  --log-dir /opt/honeyforge/logs \
  > /var/log/ship_events.log 2>&1 &
```

---

## Part 3: Verification

### Step 11: Test the honeypot from your Mac

```bash
# Test default page
curl http://<VPS-IP>/

# Test FortiGate spoof
curl -sk https://<VPS-IP>:10443/remote/login | grep FortiGate

# Send a test exploit (CVE-2024-4577)
curl -X POST "http://<VPS-IP>/index.php?%ADd+allow_url_include=1" \
  -d '<?php system("id"); ?>'
```

### Step 12: Check events arrived at central

Open Intel UI: `http://localhost:8090`

- Go to **IOCs** → click **Extract Now**
- You should see the test IP appear as an IOC
- Go to **Services** → the Oracle sensor should show as registered

### Step 13: Check sensor logs (on VPS)

```bash
# View honeypot logs
tail -f /opt/honeyforge/logs/http/http.json

# View shipper logs
tail -f /var/log/ship_events.log
```

---

## Part 4: Ongoing Operations

### Daily (automated)

- CVE Watcher polls CISA KEV + NVD (every 6h)
- IOC Extractor processes events (every 10 min)
- Event shipper sends logs to central (every 30s)
- STIX bundles auto-published on TAXII

### When you reboot your Mac

```bash
open -a Docker
cd ~/github/honeypot
make up
make expose-intel
# Note new ngrok URL — update sensor if changed
```

### When ngrok URL changes

On the VPS, restart the shipper with the new URL:

```bash
pkill -f ship_events.py
nohup python3 /opt/honeyforge/deploy/sensor/ship_events.py \
  --central-url https://NEW-URL.ngrok-free.app \
  --sensor-key "" \
  --sensor-id hp-oracle-01 \
  --log-dir /opt/honeyforge/logs \
  > /var/log/ship_events.log 2>&1 &
```

### Deploy new plugins to sensor

From your Mac:

```bash
# Sync plugins to VPS
rsync -avz /Users/seru/github/honeypot/services/http/plugins/ \
  ubuntu@<VPS-IP>:/opt/honeyforge/services/http/plugins/

# Restart honeypot on VPS to load new plugins
ssh ubuntu@<VPS-IP> "cd /opt/honeyforge && docker compose restart http-honeypot"
```

---

## Port Reference

| Port | Service | Where |
|------|---------|-------|
| 8090 | Intel UI + TAXII | Mac (localhost only) |
| 5601 | Kibana | Mac (localhost only) |
| 9200 | Elasticsearch | Mac (localhost only) |
| 22 | SSH honeypot | VPS (public) |
| 80 | HTTP honeypot | VPS (public) |
| 443 | HTTPS honeypot | VPS (public) |
| 10443 | FortiGate spoof | VPS (public) |
| 4443 | PaloAlto spoof | VPS (public) |
| 8443 | Citrix spoof | VPS (public) |
| 2200 | Operator SSH | VPS (your IP only) |

---

## Troubleshooting

**Sensor not shipping events:**
- Check shipper is running: `ps aux | grep ship_events`
- Check ngrok is running on Mac: `curl https://your-ngrok-url.app/health`
- Check logs: `tail /var/log/ship_events.log`

**No IOCs appearing on central:**
- Go to IOCs page → click Extract Now
- Check events are arriving: `curl http://localhost:8090/api/sensors/list`

**Honeypot not responding on VPS:**
- Check containers: `docker ps`
- Check firewall: `sudo ufw status`
- Check Oracle Cloud security list allows the port

**ngrok URL changed:**
- Update the shipper on VPS with new URL (see "When ngrok URL changes" above)
