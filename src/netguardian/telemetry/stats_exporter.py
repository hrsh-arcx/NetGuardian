"""
netguardian.telemetry.stats_exporter — Periodic Stats Reporter

Runs as a background asyncio task. Every `interval` seconds it takes a
metrics snapshot and renders it as a Rich table on the console and/or
writes it as a JSON line to a file — giving you a live dashboard of
proxy health without any external monitoring stack.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console
from rich.table import Table

from netguardian.telemetry.metrics import MetricsCollector


class StatsExporter:
    """Periodically exports metrics to console and/or JSON file."""

    def __init__(
        self,
        metrics: MetricsCollector,
        interval: int = 30,
        console_table: bool = True,
        json_export: bool = True,
        json_path: str = "logs/metrics.json",
    ):
        self._metrics = metrics
        self._interval = interval
        self._console_table = console_table
        self._json_export = json_export
        self._json_path = json_path
        self._console = Console()
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Launch the periodic export loop as a background task."""
        self._task = asyncio.create_task(self._export_loop())

    async def stop(self) -> None:
        """Cancel the export loop and do one final export."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        # Final snapshot on shutdown
        await self._export_once()

    async def _export_loop(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            await self._export_once()

    async def _export_once(self) -> None:
        snap = await self._metrics.snapshot()

        if self._console_table:
            self._render_console(snap)

        if self._json_export:
            self._write_json(snap)

    def _render_console(self, snap: dict) -> None:
        """Print a Rich table summarizing current metrics."""
        self._console.print()
        self._console.rule("[bold cyan]NetGuardian Stats[/]", style="cyan")

        # Uptime
        uptime = snap["uptime_seconds"]
        mins, secs = divmod(int(uptime), 60)
        hours, mins = divmod(mins, 60)
        self._console.print(
            f"  ⏱  Uptime: [bold]{hours:02d}:{mins:02d}:{secs:02d}[/]"
        )

        # Counters table
        counters = snap.get("counters", {})
        if counters:
            t = Table(title="Counters", show_header=True, header_style="bold magenta")
            t.add_column("Metric", style="cyan")
            t.add_column("Value", justify="right", style="green")
            for name, val in sorted(counters.items()):
                t.add_row(name, f"{val:,}")
            self._console.print(t)

        # Gauges table
        gauges = snap.get("gauges", {})
        if gauges:
            t = Table(title="Gauges", show_header=True, header_style="bold magenta")
            t.add_column("Metric", style="cyan")
            t.add_column("Value", justify="right", style="yellow")
            for name, val in sorted(gauges.items()):
                t.add_row(name, f"{val:,.2f}")
            self._console.print(t)

        # Histograms table
        histograms = snap.get("histograms", {})
        if histograms:
            t = Table(title="Histograms", show_header=True, header_style="bold magenta")
            t.add_column("Metric", style="cyan")
            t.add_column("Count", justify="right")
            t.add_column("Mean", justify="right", style="green")
            t.add_column("P50", justify="right")
            t.add_column("P95", justify="right", style="yellow")
            t.add_column("P99", justify="right", style="red")
            for name, data in sorted(histograms.items()):
                t.add_row(
                    name,
                    str(data["count"]),
                    f"{data['mean']:.1f}",
                    f"{data['p50']:.1f}",
                    f"{data['p95']:.1f}",
                    f"{data['p99']:.1f}",
                )
            self._console.print(t)

        self._console.rule(style="dim")

    def _write_json(self, snap: dict) -> None:
        """Append a timestamped JSON line to the export file."""
        os.makedirs(os.path.dirname(self._json_path) or ".", exist_ok=True)
        snap["exported_at"] = datetime.now(timezone.utc).isoformat()
        with open(self._json_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(snap, default=str) + "\n")
