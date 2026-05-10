"""
High-interaction SSH honeypot.

Real SSH protocol (paramiko). Captures:
  * Every authentication attempt (password + pubkey)
  * Full keystroke stream post-auth
  * Executed commands and their fake output
  * Session recording (can be replayed offline)

The shell is an emulated Ubuntu 22.04 filesystem with a curated command set.
Additional commands are registered in shell.py.
"""
from __future__ import annotations

import os
import socket
import threading
from pathlib import Path

import paramiko

from honeycore import Deception, Session, get_logger
from service.auth import AuthServer
from service.shell import EmulatedShell

LOG = get_logger("ssh")
DECEPTION = Deception.from_env()
HOST_KEY_PATH = Path("/app/host_key/ssh_host_rsa_key")


def _get_or_create_host_key() -> paramiko.RSAKey:
    """Generate a fresh RSA key per deployment — reused keys are a strong Censys tell."""
    if not HOST_KEY_PATH.exists():
        LOG.info("ssh_generating_host_key")
        key = paramiko.RSAKey.generate(2048)
        HOST_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        key.write_private_key_file(str(HOST_KEY_PATH))
    return paramiko.RSAKey(filename=str(HOST_KEY_PATH))


def handle_client(client_sock: socket.socket, src_addr: tuple[str, int]) -> None:
    session = Session(
        service="ssh",
        src_ip=src_addr[0],
        src_port=src_addr[1],
        dst_port=2222,
    )
    session.event(LOG, "ssh_connect")

    transport = paramiko.Transport(client_sock)
    transport.local_version = DECEPTION.ssh_banner
    transport.add_server_key(_get_or_create_host_key())

    try:
        auth = AuthServer(session, LOG)
        transport.start_server(server=auth)

        chan = transport.accept(timeout=30)
        if chan is None:
            session.event(LOG, "ssh_no_channel")
            return

        auth.channel_opened.wait(timeout=10)
        shell = EmulatedShell(session, LOG, DECEPTION, username=auth.authed_user or "root")
        shell.run(chan)

    except paramiko.SSHException as e:
        session.event(LOG, "ssh_protocol_error", error=str(e))
    except Exception as e:  # never crash on a single attacker
        session.event(LOG, "ssh_handler_exception", error=str(e))
    finally:
        session.event(LOG, "ssh_disconnect", duration=round(session.duration(), 2))
        try:
            transport.close()
        except Exception:
            pass


def serve(host: str = "0.0.0.0", port: int = 2222) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    LOG.info("ssh_listening",
             extra={"data": {"host": host, "port": port, "banner": DECEPTION.ssh_banner}})

    while True:
        client, addr = srv.accept()
        t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    serve(host=os.getenv("SSH_BIND", "0.0.0.0"), port=int(os.getenv("SSH_LISTEN_PORT", "2222")))
