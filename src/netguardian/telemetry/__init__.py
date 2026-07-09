"""
netguardian.telemetry — Logging, Metrics & Debugging

Provides structured logging (JSON + Rich console), in-memory metrics
collection, periodic stats export, and a raw packet hex-dump utility.
"""

from netguardian.telemetry.logger import get_logger, setup_logging
from netguardian.telemetry.metrics import MetricsCollector
from netguardian.telemetry.stats_exporter import StatsExporter
from netguardian.telemetry.packet_dumper import PacketDumper

__all__ = [
    "get_logger",
    "setup_logging",
    "MetricsCollector",
    "StatsExporter",
    "PacketDumper",
]
