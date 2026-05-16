"""
Redis honeypot — captures unauthorized access and RCE attempts.

Emulates Redis 7.x. Logs:
  - redis_command: all commands issued
  - redis_auth: AUTH attempts
  - redis_rce: CONFIG SET, MODULE LOAD, EVAL (RCE vectors)
  - redis_exfil: GET/KEYS attempts (data theft)

Common attacks: unauthorized access, crontab injection via CONFIG SET dir,
Lua script execution, module loading.
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, "/app")

from honeycore import Deception, Session, get_logger

LOG = get_logger("redis")
DECEPTION = Deception.from_env()
LISTEN_PORT = int(os.getenv("REDIS_LISTEN_PORT", "6379"))

# Fake Redis info
REDIS_VERSION = "7.2.4"
REDIS_INFO = f"""# Server
redis_version:{REDIS_VERSION}
redis_mode:standalone
os:Linux 5.15.0-88-generic x86_64
tcp_port:{LISTEN_PORT}
uptime_in_seconds:86400
uptime_in_days:1

# Clients
connected_clients:1

# Memory
used_memory:1048576
used_memory_human:1.00M

# Keyspace
db0:keys=3,expires=0,avg_ttl=0
"""


class RedisSession:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        peer = writer.get_extra_info("peername")
        self.session = Session(
            service="redis",
            src_ip=peer[0] if peer else "0.0.0.0",
            src_port=peer[1] if peer else 0,
            dst_port=LISTEN_PORT,
        )
        self.authenticated = False

    async def handle(self):
        try:
            while True:
                line = await asyncio.wait_for(self.reader.readline(), timeout=60)
                if not line:
                    break

                decoded = line.decode("utf-8", errors="replace").strip()

                # RESP protocol: commands start with *N (array of N elements)
                if decoded.startswith("*"):
                    cmd_parts = await self.read_resp_array(int(decoded[1:]))
                    if cmd_parts:
                        await self.process_command(cmd_parts)
                elif decoded:
                    # Inline command
                    parts = decoded.split()
                    if parts:
                        await self.process_command(parts)

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                self.writer.close()
            except Exception:
                pass

    async def read_resp_array(self, count: int) -> list[str]:
        """Read RESP bulk strings."""
        parts = []
        for _ in range(count):
            header = await asyncio.wait_for(self.reader.readline(), timeout=10)
            header = header.decode("utf-8", errors="replace").strip()
            if header.startswith("$"):
                length = int(header[1:])
                if length < 0:
                    parts.append("")
                    continue
                data = await self.reader.read(length + 2)  # +2 for \r\n
                parts.append(data[:length].decode("utf-8", errors="replace"))
            else:
                parts.append(header)
        return parts

    async def process_command(self, parts: list[str]):
        if not parts:
            return

        cmd = parts[0].upper()
        args = parts[1:] if len(parts) > 1 else []

        self.session.event(LOG, "redis_command", command=cmd, args=args[:5])

        DECEPTION.jitter()

        # AUTH
        if cmd == "AUTH":
            self.session.event(LOG, "redis_auth", password=args[0] if args else "")
            self.reply_error("WRONGPASS invalid username-password pair")
            return

        # RCE vectors
        if cmd == "CONFIG" and args:
            subcmd = args[0].upper() if args else ""
            if subcmd == "SET":
                self.session.event(LOG, "redis_rce",
                                   vector="config_set", args=args)
                self.reply_ok()
                return
            elif subcmd == "GET":
                self.reply_array(["dir", "/var/lib/redis"])
                return

        if cmd in ("EVAL", "EVALSHA"):
            self.session.event(LOG, "redis_rce", vector="lua_eval", script=args[0][:500] if args else "")
            self.reply_error("NOSCRIPT No matching script")
            return

        if cmd == "MODULE" and args and args[0].upper() == "LOAD":
            self.session.event(LOG, "redis_rce", vector="module_load", path=args[1] if len(args) > 1 else "")
            self.reply_error("ERR Error loading shared library")
            return

        if cmd == "SLAVEOF" or cmd == "REPLICAOF":
            self.session.event(LOG, "redis_rce", vector="replication", args=args)
            self.reply_ok()
            return

        # Data access
        if cmd in ("GET", "MGET", "KEYS", "SCAN", "DUMP"):
            self.session.event(LOG, "redis_exfil", command=cmd, args=args[:3])

        # Standard responses
        if cmd == "PING":
            self.reply_simple("PONG")
        elif cmd == "INFO":
            self.reply_bulk(REDIS_INFO)
        elif cmd == "DBSIZE":
            self.reply_integer(3)
        elif cmd == "KEYS":
            self.reply_array(["session:abc123", "user:admin", "config:app"])
        elif cmd == "GET":
            self.reply_bulk("(nil)")
        elif cmd == "SET":
            self.reply_ok()
        elif cmd == "SELECT":
            self.reply_ok()
        elif cmd == "QUIT":
            self.reply_ok()
            self.writer.close()
        elif cmd == "COMMAND":
            self.reply_ok()
        elif cmd == "CLIENT":
            self.reply_ok()
        else:
            self.reply_error(f"ERR unknown command '{parts[0]}'")

    def reply_simple(self, msg: str):
        self.writer.write(f"+{msg}\r\n".encode())

    def reply_ok(self):
        self.reply_simple("OK")

    def reply_error(self, msg: str):
        self.writer.write(f"-{msg}\r\n".encode())

    def reply_integer(self, n: int):
        self.writer.write(f":{n}\r\n".encode())

    def reply_bulk(self, data: str):
        encoded = data.encode()
        self.writer.write(f"${len(encoded)}\r\n".encode() + encoded + b"\r\n")

    def reply_array(self, items: list[str]):
        self.writer.write(f"*{len(items)}\r\n".encode())
        for item in items:
            encoded = item.encode()
            self.writer.write(f"${len(encoded)}\r\n".encode() + encoded + b"\r\n")


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    session = RedisSession(reader, writer)
    await session.handle()


async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", LISTEN_PORT)
    LOG.info("redis_honeypot_started", extra={"data": {"port": LISTEN_PORT}})
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
