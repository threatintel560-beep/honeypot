"""
SSH authentication handler.

Captures every credential attempt. Accepts a subset based on SSH_FAKE_USERS
env var so attackers land in a shell and we observe post-auth behavior.
"""
from __future__ import annotations

import logging
import os
import threading

import paramiko

from honeycore import Session


def _load_fake_creds() -> dict[str, str]:
    raw = os.getenv("SSH_FAKE_USERS", "root:toor,admin:admin")
    creds: dict[str, str] = {}
    for pair in raw.split(","):
        if ":" in pair:
            user, pw = pair.split(":", 1)
            creds[user.strip()] = pw.strip()
    return creds


class AuthServer(paramiko.ServerInterface):
    FAKE_CREDS = _load_fake_creds()

    def __init__(self, session: Session, logger: logging.Logger):
        self.session = session
        self.log = logger
        self.authed_user: str | None = None
        self.channel_opened = threading.Event()

    # ── paramiko hooks ─────────────────────────────────────────────
    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            self.channel_opened.set()
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_auth_password(self, username: str, password: str) -> int:
        self.session.event(
            self.log, "ssh_auth_password",
            username=username, password=password,
        )
        expected = self.FAKE_CREDS.get(username)
        if expected and password == expected:
            self.authed_user = username
            self.session.tag(auth_user=username, auth_method="password")
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        self.session.event(
            self.log, "ssh_auth_pubkey",
            username=username,
            key_type=key.get_name(),
            fingerprint=key.get_fingerprint().hex(),
        )
        # Never accept pubkey — forces attacker to reveal passwords
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel) -> bool:
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes) -> bool:
        self.session.event(self.log, "ssh_pty_request", term=term, w=width, h=height)
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        # direct `ssh host "cmd"` — extremely common in botnets
        cmd = command.decode("utf-8", errors="replace")
        self.session.event(self.log, "ssh_exec_request", command=cmd)
        return True
