"""
netguardian tests conftest.py

Provides pytest fixtures to start mock target HTTP servers and
local NetGuardian proxy instances for end-to-end integration tests.
"""

import asyncio
import socket
import pytest
import pytest_asyncio
from typing import Generator, Tuple

from netguardian.core.proxy_handler import ProxyHandler
from netguardian.core.server import ProxyServer
from netguardian.inspection.engine import InspectionEngine
from netguardian.inspection.signature_store import SignatureStore
from netguardian.security.auth import ProxyAuthenticator
from netguardian.security.ip_filter import IPFilter
from netguardian.security.rate_limiter import RateLimiter
from netguardian.telemetry.metrics import MetricsCollector
from netguardian.utils.graceful_shutdown import GracefulShutdown


def get_free_port() -> int:
    """Find an unused TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class MockHttpServer:
    """A lightweight mock HTTP server for testing backend integration."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.server: asyncio.AbstractServer = None
        self.last_request_headers = {}
        self.last_request_body = b""
        self.response_body = b"Mock Backend Response"
        self.response_status = "200 OK"

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
        )

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            # Simple HTTP/1.1 parsing
            data = await reader.read(4096)
            if not data:
                return

            header_part, *body_parts = data.split(b"\r\n\r\n", 1)
            self.last_request_body = body_parts[0] if body_parts else b""

            headers = {}
            lines = header_part.decode("utf-8", errors="replace").split("\r\n")
            if lines:
                for line in lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
            self.last_request_headers = headers

            # Write standard HTTP response
            resp = (
                f"HTTP/1.1 {self.response_status}\r\n"
                f"Content-Length: {len(self.response_body)}\r\n"
                f"Content-Type: text/plain\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode("utf-8") + self.response_body
            writer.write(resp)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


@pytest_asyncio.fixture
async def mock_backend() -> Generator[MockHttpServer, None, None]:
    """Start a mock HTTP backend server."""
    port = get_free_port()
    server = MockHttpServer("127.0.0.1", port)
    await server.start()
    yield server
    await server.stop()


@pytest_asyncio.fixture
async def proxy_factory():
    """Factory to spin up customized NetGuardian proxy instances."""
    servers = []

    async def _create(
        ip_filter=None,
        rate_limiter=None,
        authenticator=None,
        inspection_engine=None,
        tls_enabled=False,
    ) -> Tuple[str, int, ProxyServer]:
        host = "127.0.0.1"
        port = get_free_port()

        metrics = MetricsCollector()
        shutdown = GracefulShutdown()

        handler = ProxyHandler(
            ip_filter=ip_filter,
            rate_limiter=rate_limiter,
            authenticator=authenticator,
            inspection_engine=inspection_engine,
            tls_manager=None, # Not using full CA dynamic generation in raw unit tests without cert setup
            metrics=metrics,
            connection_timeout=5,
        )

        server = ProxyServer(
            handler=handler,
            host=host,
            port=port,
            max_connections=10,
            shutdown=shutdown,
            metrics=metrics,
        )

        # Run start in background task since it blocks on wait_for_shutdown()
        # We start the asyncio server manually to control its lifecycle
        server._server = await asyncio.start_server(
            server._on_connection,
            host=server._host,
            port=server._port,
        )

        servers.append(server)
        return host, port, server

    yield _create

    # Cleanup any running servers
    for server in servers:
        if server._server:
            server._server.close()
            await server._server.wait_closed()
