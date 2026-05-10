"""
Structured JSON logger. One line = one attacker event.

Filebeat ships /var/log/honeypot/*.json straight into Logstash. The schema is
stable: every event has ts, service, session_id, event, src_ip, src_port, data.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import sys
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any

_HOSTNAME = socket.gethostname()
_DEPLOYMENT_ID = os.getenv("HONEY_DEPLOYMENT_ID", "hp-dev")


class JSONFormatter(logging.Formatter):
    """Single-line JSON formatter keyed for the Logstash pipeline."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": getattr(record, "service", "unknown"),
            "host": _HOSTNAME,
            "deployment": _DEPLOYMENT_ID,
            "event": getattr(record, "event", record.getMessage()),
        }

        # Attach any structured extras the caller passed via `extra=`
        for k in ("session_id", "src_ip", "src_port", "dst_port",
                  "cve", "plugin", "data"):
            if hasattr(record, k):
                payload[k] = getattr(record, k)

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, separators=(",", ":"))


def get_logger(service: str, log_dir: str = "/var/log/honeypot") -> logging.Logger:
    """
    Return a configured logger for a honeypot service.

    Writes rotating JSON files to log_dir/<service>.json *and* stderr (for
    `docker logs` visibility).
    """
    log = logging.getLogger(f"hp.{service}")
    if log.handlers:
        return log  # already configured

    log.setLevel(logging.INFO)
    log.propagate = False

    fmt = JSONFormatter()

    # Stderr handler — visible via `docker logs`
    err = logging.StreamHandler(sys.stderr)
    err.setFormatter(fmt)
    log.addHandler(err)

    # File handler — picked up by Filebeat
    try:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        fh = TimedRotatingFileHandler(
            filename=f"{log_dir}/{service}.json",
            when="midnight",
            backupCount=14,
            utc=True,
        )
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except PermissionError:
        log.warning("log_dir not writable — stderr-only mode", extra={"service": service})

    # Attach the service name as a default so every record gets it
    logging.setLoggerClass(_ServiceLogger)
    log = logging.getLogger(f"hp.{service}")
    log.service_name = service  # type: ignore[attr-defined]
    return log


class _ServiceLogger(logging.Logger):
    service_name: str = "unknown"

    def _log(self, level, msg, args, **kwargs):  # type: ignore[override]
        extra = kwargs.get("extra") or {}
        extra.setdefault("service", getattr(self, "service_name", "unknown"))
        kwargs["extra"] = extra
        super()._log(level, msg, args, **kwargs)
