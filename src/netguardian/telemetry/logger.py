"""
netguardian.telemetry.logger — Structured Logging

Dual-output logger: JSON lines to rotating files + Rich-formatted console.
Each log entry carries contextual fields (connection ID, source IP, target)
so you can trace a request across the entire proxy pipeline.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Custom TRACE level (below DEBUG) for extremely verbose packet-level logs
TRACE = 5
logging.addLevelName(TRACE, "TRACE")

_console = Console(theme=Theme({
    "logging.level.trace": "dim cyan",
    "logging.level.info": "bold green",
    "logging.level.warning": "bold yellow",
    "logging.level.error": "bold red",
    "logging.level.critical": "bold white on red",
}))


class JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON for machine parsing."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Attach extra context fields if present
        for key in ("conn_id", "src_ip", "target", "action", "signature"):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = str(record.exc_info[1])
        return json.dumps(entry, default=str)


class ContextLogger(logging.LoggerAdapter):
    """Logger adapter that injects connection context into every log call."""

    def __init__(self, logger: logging.Logger, context: Optional[Dict[str, Any]] = None):
        super().__init__(logger, context or {})

    def process(self, msg, kwargs):
        extra = kwargs.setdefault("extra", {})
        extra.update(self.extra)
        return msg, kwargs

    def trace(self, msg, *args, **kwargs):
        self.log(TRACE, msg, *args, **kwargs)

    def with_context(self, **fields) -> "ContextLogger":
        """Return a new logger with additional context fields merged in."""
        merged = {**self.extra, **fields}
        return ContextLogger(self.logger, merged)


def setup_logging(
    level: str = "INFO",
    console_enabled: bool = True,
    file_enabled: bool = True,
    log_dir: str = "logs",
    max_file_size_mb: int = 10,
    json_format: bool = True,
) -> None:
    """Initialize the root NetGuardian logger with console and/or file handlers."""

    numeric_level = getattr(logging, level.upper(), None)
    if numeric_level is None:
        if level.upper() == "TRACE":
            numeric_level = TRACE
        else:
            numeric_level = logging.INFO

    root = logging.getLogger("netguardian")
    root.setLevel(numeric_level)
    root.handlers.clear()

    if console_enabled:
        rich_handler = RichHandler(
            console=_console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        rich_handler.setLevel(numeric_level)
        root.addHandler(rich_handler)

    if file_enabled:
        os.makedirs(log_dir, exist_ok=True)
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, "netguardian.log"),
            maxBytes=max_file_size_mb * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)
        if json_format:
            file_handler.setFormatter(JsonFormatter())
        else:
            file_handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
            ))
        root.addHandler(file_handler)


def get_logger(name: str = "netguardian", **context) -> ContextLogger:
    """
    Get a ContextLogger instance. Pass keyword args to attach
    persistent context fields (e.g., conn_id, src_ip).
    """
    logger = logging.getLogger(name)
    return ContextLogger(logger, context)
