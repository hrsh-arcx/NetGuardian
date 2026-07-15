"""
netguardian.core.connection — Per-Connection State Machine

Tracks the lifecycle and metadata of a single client connection
as it moves through the proxy pipeline:
  CONNECTED → AUTHENTICATED → INSPECTED → RELAYING → CLOSED
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ConnState(Enum):
    CONNECTED = "connected"
    AUTHENTICATED = "authenticated"
    INSPECTED = "inspected"
    RELAYING = "relaying"
    CLOSED = "closed"


@dataclass
class ConnectionContext:
    """Per-connection state container passed through the handler pipeline."""

    conn_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    client_addr: str = ""
    client_port: int = 0
    target_host: str = ""
    target_port: int = 0
    state: ConnState = ConnState.CONNECTED
    start_time: float = field(default_factory=time.monotonic)
    bytes_in: int = 0
    bytes_out: int = 0
    is_tls: bool = False
    authenticated_user: Optional[str] = None

    def transition(self, new_state: ConnState) -> None:
        self.state = new_state

    @property
    def duration(self) -> float:
        """Elapsed time in seconds since connection was established."""
        return time.monotonic() - self.start_time

    def summary(self) -> dict:
        return {
            "conn_id": self.conn_id,
            "client": f"{self.client_addr}:{self.client_port}",
            "target": f"{self.target_host}:{self.target_port}",
            "state": self.state.value,
            "duration_s": round(self.duration, 2),
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "tls": self.is_tls,
        }
