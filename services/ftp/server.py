"""
FTP honeypot — captures credentials and file upload attempts.

Emulates a vsftpd server. Logs:
  - ftp_auth: username/password attempts
  - ftp_command: all FTP commands issued
  - ftp_upload: file upload attempts (stores filename + first 4KB)
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, "/app")

from honeycore import Deception, Session, get_logger

LOG = get_logger("ftp")
DECEPTION = Deception.from_env()
LISTEN_PORT = int(os.getenv("FTP_LISTEN_PORT", "21"))
BANNER = "220 (vsFTPd 3.0.5)\r\n"


class FTPSession:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        peer = writer.get_extra_info("peername")
        self.session = Session(
            service="ftp",
            src_ip=peer[0] if peer else "0.0.0.0",
            src_port=peer[1] if peer else 0,
            dst_port=LISTEN_PORT,
        )
        self.authenticated = False
        self.username = ""

    async def handle(self):
        try:
            self.send(BANNER)
            while True:
                line = await asyncio.wait_for(self.reader.readline(), timeout=60)
                if not line:
                    break
                cmd = line.decode("utf-8", errors="replace").strip()
                if not cmd:
                    continue
                await self.process_command(cmd)
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                self.writer.close()
            except Exception:
                pass

    async def process_command(self, raw: str):
        parts = raw.split(" ", 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        self.session.event(LOG, "ftp_command", command=cmd, argument=arg)

        if cmd == "USER":
            self.username = arg
            self.send("331 Please specify the password.\r\n")
        elif cmd == "PASS":
            self.session.event(LOG, "ftp_auth",
                               username=self.username, password=arg)
            # Always reject — capture creds
            DECEPTION.jitter()
            self.send("530 Login incorrect.\r\n")
        elif cmd == "QUIT":
            self.send("221 Goodbye.\r\n")
            self.writer.close()
        elif cmd == "SYST":
            self.send("215 UNIX Type: L8\r\n")
        elif cmd == "FEAT":
            self.send("211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n")
        elif cmd == "PWD":
            self.send('257 "/" is the current directory\r\n')
        elif cmd == "TYPE":
            self.send("200 Switching to Binary mode.\r\n")
        elif cmd == "PASV":
            self.send("227 Entering Passive Mode (127,0,0,1,0,0).\r\n")
        elif cmd in ("STOR", "PUT"):
            self.session.event(LOG, "ftp_upload", filename=arg)
            self.send("550 Permission denied.\r\n")
        elif cmd in ("LIST", "NLST"):
            self.send("150 Here comes the directory listing.\r\n")
            self.send("226 Directory send OK.\r\n")
        elif cmd == "CWD":
            self.send("250 Directory successfully changed.\r\n")
        elif cmd == "MKD":
            self.send("550 Permission denied.\r\n")
        else:
            self.send(f"502 Command not implemented.\r\n")

    def send(self, data: str):
        try:
            self.writer.write(data.encode())
        except Exception:
            pass


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    session = FTPSession(reader, writer)
    await session.handle()


async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", LISTEN_PORT)
    LOG.info("ftp_honeypot_started", extra={"data": {"port": LISTEN_PORT}})
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
