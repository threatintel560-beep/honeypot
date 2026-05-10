"""
Attacker session abstraction — same shape for SSH, HTTP, and future protocols.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Session:
    """One attacker interaction. Lives from connect to disconnect."""

    service: str
    src_ip: str
    src_port: int
    dst_port: int
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    started_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    # ── event emission ────────────────────────────────────────────────
    def event(self, logger: logging.Logger, event: str, **data: Any) -> None:
        """Emit a structured event bound to this session."""
        logger.info(
            event,
            extra={
                "event": event,
                "session_id": self.session_id,
                "src_ip": self.src_ip,
                "src_port": self.src_port,
                "dst_port": self.dst_port,
                "data": data or None,
            },
        )

    def duration(self) -> float:
        return time.time() - self.started_at

    def tag(self, **kv: Any) -> None:
        """Attach arbitrary metadata (e.g. captured credentials, detected CVE)."""
        self.metadata.update(kv)
