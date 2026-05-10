"""
Emulated Linux shell — enough realism to keep a bot interacting for minutes
and capture its full dropper chain.

Command handlers are a simple dict; adding `uname -a` or `curl` is one entry.
"""
from __future__ import annotations

import logging
import shlex
import time
from typing import Callable

from honeycore import Deception, Session

CommandHandler = Callable[[list[str], "EmulatedShell"], str]


class EmulatedShell:
    MAX_CMDS_PER_SESSION = 250

    def __init__(self, session: Session, logger: logging.Logger,
                 deception: Deception, username: str = "root"):
        self.session = session
        self.log = logger
        self.deception = deception
        self.user = username
        self.cwd = "/root" if username == "root" else f"/home/{username}"
        self.commands: dict[str, CommandHandler] = self._build_commands()

    # ── main loop ──────────────────────────────────────────────────
    def run(self, chan) -> None:
        chan.send(self.deception.motd().replace("\n", "\r\n").encode())
        chan.send(self.deception.shell_prompt(self.user).encode())

        buf = bytearray()
        cmd_count = 0

        while True:
            try:
                data = chan.recv(1024)
            except Exception:
                break
            if not data:
                break

            for byte in data:
                if byte in (3, 4):  # Ctrl-C / Ctrl-D
                    chan.send(b"\r\n")
                    if byte == 4:
                        chan.send(b"logout\r\n")
                        return
                    buf.clear()
                    chan.send(self.deception.shell_prompt(self.user).encode())
                    continue

                if byte in (10, 13):  # CR / LF
                    chan.send(b"\r\n")
                    line = buf.decode("utf-8", errors="replace").strip()
                    buf.clear()
                    if line:
                        cmd_count += 1
                        if cmd_count > self.MAX_CMDS_PER_SESSION:
                            chan.send(b"Connection reset by peer\r\n")
                            return
                        out = self._dispatch(line)
                        if out == "__EXIT__":
                            chan.send(b"logout\r\n")
                            return
                        if out:
                            chan.send(out.replace("\n", "\r\n").encode())
                            if not out.endswith("\n"):
                                chan.send(b"\r\n")
                    chan.send(self.deception.shell_prompt(self.user).encode())
                    continue

                if byte == 127:  # backspace
                    if buf:
                        buf.pop()
                        chan.send(b"\b \b")
                    continue

                buf.append(byte)
                chan.send(bytes([byte]))  # echo

    # ── dispatch ───────────────────────────────────────────────────
    def _dispatch(self, line: str) -> str:
        self.session.event(self.log, "ssh_command", command=line)
        self.deception.jitter()

        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        if not parts:
            return ""

        cmd, args = parts[0], parts[1:]

        # Chain support: `a; b` or `a && b` — handled naively
        if ";" in line or "&&" in line:
            out = []
            for sub in line.replace("&&", ";").split(";"):
                sub = sub.strip()
                if sub:
                    out.append(self._dispatch(sub))
            return "\n".join(o for o in out if o)

        handler = self.commands.get(cmd)
        if handler:
            return handler(args, self)

        # Fallback: realistic "not found"
        return f"{cmd}: command not found"

    # ── command table ──────────────────────────────────────────────
    def _build_commands(self) -> dict[str, CommandHandler]:
        return {
            "exit": lambda a, s: "__EXIT__",
            "logout": lambda a, s: "__EXIT__",
            "whoami": lambda a, s: s.user,
            "id": lambda a, s: f"uid=0(root) gid=0(root) groups=0(root)" if s.user == "root"
                               else f"uid=1000({s.user}) gid=1000({s.user}) groups=1000({s.user})",
            "pwd": lambda a, s: s.cwd,
            "hostname": lambda a, s: s.deception.hostname,
            "uname": _cmd_uname,
            "ls": _cmd_ls,
            "cat": _cmd_cat,
            "echo": lambda a, s: " ".join(a),
            "ps": _cmd_ps,
            "ifconfig": _cmd_ifconfig,
            "ip": _cmd_ip,
            "netstat": _cmd_netstat,
            "ss": _cmd_netstat,
            "w": lambda a, s: _cmd_w(a, s),
            "uptime": _cmd_uptime,
            "history": lambda a, s: "",
            "wget": _cmd_download,
            "curl": _cmd_download,
            "cd": _cmd_cd,
            "clear": lambda a, s: "\033[H\033[2J",
            "df": _cmd_df,
            "free": _cmd_free,
            "crontab": lambda a, s: "no crontab for " + s.user,
            "sudo": lambda a, s: f"[sudo] password for {s.user}: \nsudo: a password is required",
        }


# ── individual command implementations ────────────────────────────
def _cmd_uname(args, s: EmulatedShell) -> str:
    if "-a" in args:
        return (f"Linux {s.deception.hostname} 5.15.0-88-generic #98-Ubuntu SMP "
                f"Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux")
    return "Linux"


def _cmd_ls(args, s: EmulatedShell) -> str:
    long = "-l" in args or "-la" in args or "-al" in args
    fake = {
        "/root": [".bash_history", ".bashrc", ".profile", ".ssh", ".cache"],
        "/home/ubuntu": [".bashrc", ".profile", ".ssh", "snap"],
        "/": ["bin", "boot", "dev", "etc", "home", "lib", "media", "mnt",
              "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"],
    }.get(s.cwd, [])
    if not long:
        return "  ".join(fake)
    lines = ["total 52"]
    for name in fake:
        lines.append(f"drwxr-xr-x 2 {s.user} {s.user} 4096 Oct  5 12:34 {name}")
    return "\n".join(lines)


def _cmd_cat(args, s: EmulatedShell) -> str:
    if not args:
        return ""
    target = args[0]
    fake_files = {
        "/etc/passwd": ("root:x:0:0:root:/root:/bin/bash\n"
                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                        f"{s.user}:x:1000:1000:{s.user.title()}:/home/{s.user}:/bin/bash\n"),
        "/etc/shadow": "cat: /etc/shadow: Permission denied",
        "/etc/hostname": s.deception.hostname,
        "/etc/os-release": ('PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\n'
                            'VERSION_ID="22.04"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
                            'ID=ubuntu\n'),
        "/proc/cpuinfo": ("processor\t: 0\nvendor_id\t: GenuineIntel\n"
                          "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"),
    }
    return fake_files.get(target, f"cat: {target}: No such file or directory")


def _cmd_ps(args, s: EmulatedShell) -> str:
    return ("  PID TTY          TIME CMD\n"
            "  832 pts/0    00:00:00 bash\n"
            " 1024 pts/0    00:00:00 ps")


def _cmd_ifconfig(args, s: EmulatedShell) -> str:
    return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.0.15  netmask 255.255.255.0  broadcast 10.0.0.255\n"
            "        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)\n"
            "        RX packets 12847  bytes 1842910 (1.8 MB)\n"
            "        TX packets 9821  bytes 1248392 (1.2 MB)\n")


def _cmd_ip(args, s: EmulatedShell) -> str:
    if args and args[0] in ("a", "addr"):
        return _cmd_ifconfig([], s)
    return ""


def _cmd_netstat(args, s: EmulatedShell) -> str:
    return ("Active Internet connections\n"
            "tcp  0  0 0.0.0.0:22   0.0.0.0:*   LISTEN\n"
            "tcp  0  0 0.0.0.0:80   0.0.0.0:*   LISTEN\n")


def _cmd_w(args, s: EmulatedShell) -> str:
    t = time.strftime("%H:%M:%S")
    return (f" {t} up  3 days,  2:14,  1 user,  load average: 0.02, 0.05, 0.01\n"
            f"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            f"{s.user:<9}pts/0    {s.session.src_ip:<16} {t}   0.00s  0.01s  0.00s w")


def _cmd_uptime(args, s: EmulatedShell) -> str:
    t = time.strftime("%H:%M:%S")
    return f" {t} up 3 days,  2:14,  1 user,  load average: 0.02, 0.05, 0.01"


def _cmd_cd(args, s: EmulatedShell) -> str:
    if not args or args[0] == "~":
        s.cwd = "/root" if s.user == "root" else f"/home/{s.user}"
    elif args[0].startswith("/"):
        s.cwd = args[0]
    else:
        s.cwd = s.cwd.rstrip("/") + "/" + args[0]
    return ""


def _cmd_df(args, s: EmulatedShell) -> str:
    return ("Filesystem     1K-blocks    Used Available Use% Mounted on\n"
            "/dev/vda1       82393968 4821472  73369400   7% /\n"
            "tmpfs            2033240       0   2033240   0% /dev/shm")


def _cmd_free(args, s: EmulatedShell) -> str:
    return ("               total        used        free      shared  buff/cache   available\n"
            "Mem:         4066480      412384     2984912        1204      669184     3398308\n"
            "Swap:              0           0           0")


def _cmd_download(args, s: EmulatedShell) -> str:
    """
    wget / curl — we don't actually fetch, but we extract and log URLs
    because malware droppers are the highest-value artifact we capture.
    """
    url = None
    for a in args:
        if a.startswith(("http://", "https://", "ftp://", "tftp://")):
            url = a
            break
    if url:
        s.session.event(s.log, "ssh_dropper_url", url=url, full_cmd=" ".join(args))
        # Give realistic-looking feedback
        return (f"--2025-05-10 12:34:56--  {url}\n"
                f"Resolving {url.split('/')[2]} (...)... 1.2.3.4\n"
                f"Connecting to ...|1.2.3.4|:80... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: 4823 (4.7K) [application/octet-stream]\n"
                f"Saving to: '{url.split('/')[-1] or 'index.html'}'\n\n"
                f"100%[===============>] 4,823  --.-KB/s    in 0.01s\n")
    return ""
