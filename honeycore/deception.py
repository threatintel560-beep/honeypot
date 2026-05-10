"""
Deception engine — the bits that keep this honeypot off Censys/Shodan tags.

Censys fingerprints honeypots by matching:
  * Default Cowrie/Dionaea banners & prompts
  * Static SSH host keys reused across deployments
  * Suspicious combinations (e.g. "OpenSSH_6.0p1 Debian" + filesystem that claims CentOS)
  * Response timing that is too uniform
  * Error strings that frameworks emit literally

Deception randomizes those surfaces per-deployment and adds timing jitter.
"""
from __future__ import annotations

import hashlib
import os
import random
import time
from dataclasses import dataclass

# Realistic banners sampled from current fleet data. Update periodically.
_SSH_BANNERS = [
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
    "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u2",
    "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7",
    "SSH-2.0-OpenSSH_9.3p1 Debian-1",
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
    "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4",
]

_HTTP_SERVERS = [
    "Apache/2.4.52 (Ubuntu)",
    "Apache/2.4.41 (Ubuntu)",
    "nginx/1.18.0 (Ubuntu)",
    "nginx/1.22.1",
    "Microsoft-IIS/10.0",
    "Apache/2.4.57 (Debian)",
]

_HOSTNAMES = [
    "web-prod-01", "app-server", "db-backup", "jenkins-ci", "build-01",
    "mail-relay", "api-gw-02", "log-collector", "staging-03",
]


@dataclass
class Deception:
    """Per-deployment deception profile. Stable within a container lifecycle."""

    ssh_banner: str
    http_server: str
    hostname: str
    jitter_min_ms: int
    jitter_max_ms: int
    strict: bool

    @classmethod
    def from_env(cls) -> "Deception":
        seed = os.getenv("HONEY_DEPLOYMENT_ID", "dev") + str(os.getpid())
        rng = random.Random(hashlib.sha256(seed.encode()).hexdigest())

        def pick(env_key: str, pool: list[str]) -> str:
            val = os.getenv(env_key, "auto")
            return rng.choice(pool) if val == "auto" else val

        return cls(
            ssh_banner=pick("SSH_BANNER", _SSH_BANNERS),
            http_server=pick("HTTP_SERVER_HEADER", _HTTP_SERVERS),
            hostname=pick("SSH_HOSTNAME", _HOSTNAMES),
            jitter_min_ms=int(os.getenv("RESPONSE_JITTER_MIN", "10")),
            jitter_max_ms=int(os.getenv("RESPONSE_JITTER_MAX", "120")),
            strict=os.getenv("DECEPTION_STRICT", "true").lower() == "true",
        )

    def jitter(self) -> None:
        """Block for a random small interval to break timing fingerprints."""
        ms = random.randint(self.jitter_min_ms, self.jitter_max_ms)
        time.sleep(ms / 1000.0)

    # Small helpers for honeypot services
    def ssh_kex_greeting(self) -> str:
        return f"{self.ssh_banner}\r\n"

    def shell_prompt(self, user: str = "root") -> str:
        return f"{user}@{self.hostname}:~# "

    def motd(self) -> str:
        return (
            f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\n\n"
            f" * Documentation:  https://help.ubuntu.com\n"
            f" * Management:     https://landscape.canonical.com\n"
            f" * Support:        https://ubuntu.com/advantage\n\n"
            f"Last login: {time.strftime('%a %b %d %H:%M:%S %Y')} from 10.0.0.1\n"
        )
