"""
netguardian.core.server — Async TCP Proxy Server

The main asyncio server that listens for connections and dispatches
them to the ProxyHandler. Manages connection limits, graceful shutdown,
and the startup banner.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from netguardian import __version__
from netguardian.core.proxy_handler import ProxyHandler
from netguardian.telemetry.logger import get_logger
from netguardian.telemetry.metrics import MetricsCollector
from netguardian.utils.graceful_shutdown import GracefulShutdown

_log = get_logger("netguardian.core.server")
_console = Console()


class ProxyServer:
    """
    Main asyncio TCP server.
    Accepts connections and dispatches them to the handler pipeline.
    """

    def __init__(
        self,
        handler: ProxyHandler,
        host: str = "127.0.0.1",
        port: int = 8080,
        max_connections: int = 1024,
        shutdown: Optional[GracefulShutdown] = None,
        metrics: Optional[MetricsCollector] = None,
    ):
        self._handler = handler
        self._host = host
        self._port = port
        self._max_connections = max_connections
        self._shutdown = shutdown or GracefulShutdown()
        self._metrics = metrics
        self._server: Optional[asyncio.AbstractServer] = None
        self._semaphore = asyncio.Semaphore(max_connections)

    async def start(self) -> None:
        """Start the proxy server and listen for connections."""
        self._server = await asyncio.start_server(
            self._on_connection,
            host=self._host,
            port=self._port,
        )

        self._print_banner()
        _log.info(f"Listening on {self._host}:{self._port}")

        self._shutdown.register_signals()

        async with self._server:
            # Wait until a shutdown signal is received
            await self._shutdown.wait_for_shutdown()
            _log.info("Shutdown signal received, draining connections...")
            await self._shutdown.drain()
            _log.info("All connections drained. Server stopped.")

    async def _on_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Called for each new TCP connection."""
        if self._shutdown.is_shutting_down:
            writer.close()
            return

        # Enforce connection limit via semaphore
        acquired = self._semaphore._value > 0  # check without blocking
        if not acquired:
            _log.warning("Max connections reached, rejecting")
            writer.close()
            return

        async with self._semaphore:
            task = asyncio.current_task()
            if task:
                self._shutdown.track_task(task)
            await self._handler.handle(reader, writer)

    def _print_banner(self) -> None:
        """Display the startup banner using Rich."""
        banner_text = Text()
        banner_text.append("+---------------------------------------+\n", style="bold cyan")
        banner_text.append("|       ", style="bold cyan")
        banner_text.append("NetGuardian", style="bold white")
        banner_text.append(f" v{__version__}", style="dim white")
        banner_text.append("              |\n", style="bold cyan")
        banner_text.append("|  ", style="bold cyan")
        banner_text.append("High-Performance Infrastructure Proxy", style="dim")
        banner_text.append("  |\n", style="bold cyan")
        banner_text.append("+---------------------------------------+", style="bold cyan")

        _console.print()
        _console.print(banner_text)
        _console.print()

        info = (
            f"  [+] Listening on [bold green]{self._host}:{self._port}[/]\n"
            f"  [*] Max connections: [bold]{self._max_connections}[/]\n"
            f"  [!] Press [bold yellow]Ctrl+C[/] to stop"
        )
        _console.print(info)
        _console.print()
