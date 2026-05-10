# Anti-detection playbook

Honeypots get tagged by Censys, Shodan, and GreyNoise when they emit static
fingerprints that differ from the real services they imitate. This project
addresses the common tells; below is the checklist we maintain per release.

## Things Censys looks for (and what we do about them)

| Fingerprint | Mitigation |
|---|---|
| Static SSH host key reused across deployments | Fresh RSA-2048 key generated on first boot (`scripts/gen_hostkey.sh`). Rotate regularly with `make rotate`. |
| Default Cowrie/Dionaea banner strings | Banner pool in `honeycore/deception.py` — sampled per deployment; never return a literal framework default. |
| Identical response timing to every request | `Deception.jitter()` — 10-120 ms random delay on each response. |
| `Server:` header mismatch vs content | Single `Server` header set from the same deception profile as the default HTML page. |
| Commands return fabricated output that real Linux never prints | Review `services/ssh/shell.py` periodically; match real Ubuntu 22.04 `uname -a`, `/etc/os-release`, `df`, `free` output. |
| `OpenSSH_6.0p1 Debian-4+deb7u2` (EoL) + modern ciphers | Banner pool only contains current in-support versions. |
| Known honeypot ports (e.g. 2222 externally visible) | Recommended deploy pattern: front-end NAT maps public `:22` and `:80/443` to the internal `2222/8080`. Attacker sees standard ports. |
| Same `/etc/passwd` content on every Cowrie install | Our `cat /etc/passwd` builds the response from the attacker's logged-in username so it varies. |
| Reverse DNS on the IP screams "honeypot.tld" | Out of scope for code, but: don't put the honeypot on IPs with rDNS containing "honey", "research", "sec". |

## Pre-deploy checklist

1. `make rotate` to generate a fresh host key.
2. Set `HONEY_DEPLOYMENT_ID` to a unique value per host.
3. Map `22 → 2222` and `80/443 → 8080` via host firewall or load balancer.
4. Put the honeypot IP range outside of obvious security-org ASNs when possible.
5. Block **outbound** network from the honeypot containers — this is enforced by
   `cap_drop: ALL`, but also add iptables / cloud firewall egress rules.
6. Periodically (monthly) refresh the banner pool from the current Ubuntu / Debian fleet.

## Detection telemetry you should monitor

- Sudden drop in unique source IPs → you may have been flagged.
- Bots performing handshake then disconnecting without a single command → fingerprint tool.
- Requests with `User-Agent: CensysInspect/*` or `Shodan*` — log them and decide whether to drop or continue serving.

## Known not-yet-addressed tells

- We do not emulate kernel behavior inside `/proc` beyond `/proc/cpuinfo`. Deep scanners that read `/proc/net/tcp` will notice; solution (future): extend `shell.py` with a lazy `/proc` VFS.
- Our HTTP service does not implement TLS. In production, terminate TLS at a real nginx/haproxy in front of the honeypot; the reverse proxy presents a proper TLS stack and forwards to 8080.
