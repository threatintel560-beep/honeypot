"""
Telnet honeypot — captures IoT botnet credentials and commands.

Emulates a Linux busybox device (router/camera/IoT). Logs:
  - telnet_auth: username/password attempts
  - telnet_command: commands issued after "login"
  - telnet_dropper: wget/curl URLs detected in commands

Mirai and similar botnets target telnet with default creds.
"""
from __future__ import annotations

import asyncio
import os
import re
import sys

sys.path.insert(0, "/app")

from honeycore import Deception, Session, get_logger

LOG = get_logger("telnet")
DECEPTION = Deception.from_env()
LISTEN_PORT = int(os.getenv("TELNET_LISTEN_PORT", "23"))

URL_RE = re.compile(r'(?:https?|ftp|tftp)://[^\s\'"<>`()]+', re.IGNORECASE)

# Common IoT default creds that botnets try
ACCEPT_CREDS = {
    ("root", "root"), ("admin", "admin"), ("root", ""),
    ("admin", "password"), ("root", "toor"), ("admin", "1234"),
    ("user", "user"), ("root", "vizxv"), ("root", "xc3511"),
}

FAKE_UNAME = "Linux gateway 4.14.90 #1 SMP PREEMPT armv7l GNU/Linux"
FAKE_PS = """  PID USER       VSZ STAT COMMAND
    1 root      1200 S    init
    2 root         0 SW   [kthreadd]
  312 root      1200 S    /usr/sbin/telnetd
  445 root      1200 S    /usr/sbin/httpd
  501 root       900 S    /bin/sh
"""


class TelnetSession:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        peer = writer.get_extra_info("peername")
        self.session = Session(
            service="telnet",
            src_ip=peer[0] if peer else "0.0.0.0",
            src_port=peer[1] if peer else 0,
            dst_port=LISTEN_PORT,
        )
        self.authenticated = False
        self.username = ""

    async def handle(self):
        try:
            # Login prompt
            self.send("\r\ngateway login: ")
            username = await self.readline()
            self.username = username

            self.send("Password: ")
            password = await self.readline()

            self.session.event(LOG, "telnet_auth",
                               username=username, password=password)

            DECEPTION.jitter()

            if (username, password) in ACCEPT_CREDS:
                self.authenticated = True
                self.send(f"\r\nBusyBox v1.30.1 () built-in shell (ash)\r\n\r\n")
                await self.shell_loop()
            else:
                self.send("\r\nLogin incorrect\r\n")
                # Give them one more try
                self.send("\r\ngateway login: ")
                username = await self.readline()
                self.send("Password: ")
                password = await self.readline()
                self.session.event(LOG, "telnet_auth",
                                   username=username, password=password)
                self.send("\r\nLogin incorrect\r\n")

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                self.writer.close()
            except Exception:
                pass

    async def shell_loop(self):
        """Fake shell after successful login."""
        while True:
            self.send("# ")
            cmd = await self.readline()
            if not cmd:
                break

            self.session.event(LOG, "telnet_command", command=cmd)

            # Check for dropper URLs
            urls = URL_RE.findall(cmd)
            if urls:
                self.session.event(LOG, "telnet_dropper", urls=urls, command=cmd)

            # Respond to common commands
            response = self.fake_response(cmd)
            if response:
                self.send(response + "\r\n")

            if cmd.strip() in ("exit", "quit", "logout"):
                break

    def fake_response(self, cmd: str) -> str:
        cmd_lower = cmd.strip().lower()
        if cmd_lower.startswith("uname"):
            return FAKE_UNAME
        elif cmd_lower == "id":
            return "uid=0(root) gid=0(root)"
        elif cmd_lower == "whoami":
            return "root"
        elif cmd_lower == "pwd":
            return "/root"
        elif cmd_lower.startswith("cat /proc/cpuinfo"):
            return "processor\t: 0\nmodel name\t: ARMv7 Processor rev 4 (v7l)\nBogoMIPS\t: 38.40"
        elif cmd_lower == "ps" or cmd_lower == "ps aux":
            return FAKE_PS
        elif cmd_lower.startswith("wget") or cmd_lower.startswith("curl"):
            return ""  # Silently "succeed" — attacker thinks download worked
        elif cmd_lower.startswith("chmod"):
            return ""
        elif cmd_lower.startswith("./") or cmd_lower.startswith("/tmp/"):
            return ""  # Pretend to execute
        elif cmd_lower == "ls":
            return ""
        elif cmd_lower.startswith("cd"):
            return ""
        elif cmd_lower.startswith("echo"):
            return cmd[5:].strip()
        return f"sh: {cmd.split()[0]}: not found" if cmd.strip() else ""

    async def readline(self) -> str:
        data = await asyncio.wait_for(self.reader.readline(), timeout=30)
        return data.decode("utf-8", errors="replace").strip()

    def send(self, data: str):
        try:
            self.writer.write(data.encode())
        except Exception:
            pass


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    session = TelnetSession(reader, writer)
    await session.handle()


async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", LISTEN_PORT)
    LOG.info("telnet_honeypot_started", extra={"data": {"port": LISTEN_PORT}})
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
