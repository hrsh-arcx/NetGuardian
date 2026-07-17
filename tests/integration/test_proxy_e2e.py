"""
End-to-End integration tests for the NetGuardian proxy.

Covers:
  - Plain HTTP proxy forwarding (Step 59)
  - HTTPS CONNECT tunneling (Step 60)
  - IDS/IPS blocking (Step 61)
  - IP filtering allowlist/blocklist (Step 62)
"""

import asyncio
import pytest
import socket
from typing import Tuple

from netguardian.inspection.engine import InspectionEngine
from netguardian.inspection.signature_store import SignatureStore
from netguardian.security.ip_filter import IPFilter
from netguardian.security.rate_limiter import RateLimiter


async def send_raw_http(
    proxy_host: str,
    proxy_port: int,
    request_bytes: bytes,
) -> bytes:
    """Send raw bytes to the proxy and return all response bytes received."""
    try:
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    except Exception:
        return b""

    try:
        writer.write(request_bytes)
        await writer.drain()

        # Read until EOF
        response = b""
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            response += chunk
        return response
    except (ConnectionResetError, OSError):
        return b""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════
#  HTTP Proxy Forwarding (Step 59)
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_http_proxy_forwarding(mock_backend, proxy_factory):
    """Verify that a standard HTTP GET request is successfully forwarded."""
    # Start proxy without filtering or inspection
    host, port, _ = await proxy_factory()

    # Formulate a proxy request pointing to the mock backend
    req = (
        f"GET http://{mock_backend.host}:{mock_backend.port}/index.html HTTP/1.1\r\n"
        f"Host: {mock_backend.host}:{mock_backend.port}\r\n"
        f"User-Agent: integration-test\r\n"
        f"\r\n"
    ).encode("utf-8")

    response = await send_raw_http(host, port, req)

    # Check response from backend was received
    assert b"200 OK" in response
    assert mock_backend.response_body in response
    # Verify mock backend received headers
    assert mock_backend.last_request_headers.get("user-agent") == "integration-test"


# ═══════════════════════════════════════════════════════════════════
#  HTTPS CONNECT Tunneling (Step 60)
# ═══════════════════════════════════════════════════════════════════

class MockTcpServer:
    """Lightweight TCP Echo Server to test CONNECT tunnels."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.server: asyncio.AbstractServer = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, self.host, self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            data = await reader.read(1024)
            if data:
                # Echo back with a prefix
                writer.write(b"ECHO: " + data)
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()


@pytest.mark.asyncio
async def test_https_connect_tunneling(proxy_factory):
    """Verify that a CONNECT tunnel passes raw TCP traffic bidirectionally."""
    # Start proxy and mock TCP destination
    host, port, _ = await proxy_factory()

    dest_port = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        dest_port = s.getsockname()[1]

    tcp_server = MockTcpServer("127.0.0.1", dest_port)
    await tcp_server.start()

    try:
        # Establish connection to proxy
        reader, writer = await asyncio.open_connection(host, port)

        # Send CONNECT request
        connect_req = (
            f"CONNECT 127.0.0.1:{dest_port} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{dest_port}\r\n"
            f"\r\n"
        ).encode("utf-8")
        writer.write(connect_req)
        await writer.drain()

        # Check proxy responds with 200 Established
        response = await reader.read(4096)
        assert b"200 Connection Established" in response

        # Send raw data through the established tunnel
        writer.write(b"Hello over tunnel")
        await writer.drain()

        # Read response from the echo server
        tunnel_response = await reader.read(4096)
        assert tunnel_response == b"ECHO: Hello over tunnel"

        writer.close()
        await writer.wait_closed()

    finally:
        await tcp_server.stop()


# ═══════════════════════════════════════════════════════════════════
#  IDS/IPS Blocking (Step 61)
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_ids_ips_blocking(mock_backend, proxy_factory):
    """Verify that malicious request payloads are blocked by the IPS."""
    # Setup signature store with SQLi signatures
    sig_store = SignatureStore()
    # Add a mock block signature
    import re
    from netguardian.inspection.signature_store import Signature
    test_sig = Signature(
        id="TEST-BLOCK-001",
        name="Test Block Rule",
        category="sqli",
        severity="high",
        action="block",
        target="uri",
        pattern=r"evil-exploit",
        compiled=re.compile(r"evil-exploit")
    )
    sig_store._signatures.append(test_sig)
    sig_store._by_id[test_sig.id] = test_sig

    engine = InspectionEngine(signature_store=sig_store, mode="ips")

    host, port, _ = await proxy_factory(inspection_engine=engine)

    # Malicious request in URI
    req = (
        f"GET http://{mock_backend.host}:{mock_backend.port}/?exploit=evil-exploit HTTP/1.1\r\n"
        f"Host: {mock_backend.host}:{mock_backend.port}\r\n"
        f"\r\n"
    ).encode("utf-8")

    response = await send_raw_http(host, port, req)

    # Proxy should respond with 403 Forbidden
    assert b"403 Forbidden" in response
    assert b"Blocked by NetGuardian IPS" in response


# ═══════════════════════════════════════════════════════════════════
#  IP Filtering (Step 62)
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_ip_filtering_block(mock_backend, proxy_factory):
    """Verify that blocked client IPs are immediately dropped."""
    # Block local loopback
    ip_filter = IPFilter(blocklist=["127.0.0.1"], default_policy="allow")

    host, port, _ = await proxy_factory(ip_filter=ip_filter)

    req = (
        f"GET http://{mock_backend.host}:{mock_backend.port}/index.html HTTP/1.1\r\n"
        f"Host: {mock_backend.host}:{mock_backend.port}\r\n"
        f"\r\n"
    ).encode("utf-8")

    # Connection should be closed immediately with no response data
    response = await send_raw_http(host, port, req)
    assert response == b""
