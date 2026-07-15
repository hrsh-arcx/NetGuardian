"""
netguardian.core.proxy_handler — Request Handler

The main coroutine that processes each client connection through
the full security pipeline:

  1. Read & parse the HTTP request
  2. IP filter check
  3. Rate limit check
  4. Proxy authentication
  5. IDS/IPS inspection
  6. Forward (HTTP) or tunnel (HTTPS CONNECT)
"""

from __future__ import annotations

import asyncio
from typing import Optional

from netguardian.core.connection import ConnectionContext, ConnState
from netguardian.core.tunnel import relay
from netguardian.inspection.actions import InspectionAction
from netguardian.inspection.engine import InspectionEngine
from netguardian.protocol.http_parser import (
    HttpParser, RESPONSE_400, RESPONSE_403, RESPONSE_429,
    RESPONSE_502, RESPONSE_504, CONNECT_200,
)
from netguardian.security.auth import ProxyAuthenticator
from netguardian.security.ip_filter import IPFilter, FilterAction
from netguardian.security.rate_limiter import RateLimiter
from netguardian.security.tls_manager import CertificateManager
from netguardian.telemetry.logger import get_logger
from netguardian.telemetry.metrics import MetricsCollector

_log = get_logger("netguardian.core.handler")


class ProxyHandler:
    """Handles a single client connection through the full proxy pipeline."""

    def __init__(
        self,
        ip_filter: Optional[IPFilter] = None,
        rate_limiter: Optional[RateLimiter] = None,
        authenticator: Optional[ProxyAuthenticator] = None,
        inspection_engine: Optional[InspectionEngine] = None,
        tls_manager: Optional[CertificateManager] = None,
        metrics: Optional[MetricsCollector] = None,
        connection_timeout: int = 30,
        buffer_size: int = 65536,
    ):
        self._ip_filter = ip_filter
        self._rate_limiter = rate_limiter
        self._auth = authenticator
        self._inspector = inspection_engine
        self._tls = tls_manager
        self._metrics = metrics
        self._timeout = connection_timeout
        self._buffer_size = buffer_size

    async def handle(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Main entry point for each accepted connection."""
        peername = client_writer.get_extra_info("peername", ("unknown", 0))
        ctx = ConnectionContext(
            client_addr=str(peername[0]),
            client_port=int(peername[1]) if len(peername) > 1 else 0,
        )
        log = _log.with_context(conn_id=ctx.conn_id, src_ip=ctx.client_addr)

        try:
            if self._metrics:
                await self._metrics.adjust_gauge("active_connections", 1)
                await self._metrics.increment("connections_total")

            log.info(f"New connection from {ctx.client_addr}:{ctx.client_port}")

            # ── Step 1: IP Filter ──
            if self._ip_filter:
                result = self._ip_filter.check(ctx.client_addr)
                if result.action == FilterAction.DENY:
                    log.warning(f"IP blocked: {result.matched_rule}")
                    client_writer.close()
                    return

            # ── Step 2: Rate Limit ──
            if self._rate_limiter:
                rl_result = self._rate_limiter.check(ctx.client_addr)
                if not rl_result.allowed:
                    log.warning(f"Rate limited (remaining: {rl_result.remaining_tokens:.1f})")
                    client_writer.write(RESPONSE_429)
                    await client_writer.drain()
                    client_writer.close()
                    return

            # ── Step 3: Read HTTP Request ──
            parser = HttpParser()
            try:
                raw = await asyncio.wait_for(
                    client_reader.read(self._buffer_size),
                    timeout=self._timeout,
                )
            except asyncio.TimeoutError:
                log.debug("Read timeout waiting for request")
                client_writer.write(RESPONSE_504)
                await client_writer.drain()
                client_writer.close()
                return

            if not raw:
                client_writer.close()
                return

            parser.feed(raw)
            try:
                request = parser.parse_request()
            except Exception as e:
                log.warning(f"Parse error: {e}")
                client_writer.write(RESPONSE_400)
                await client_writer.drain()
                client_writer.close()
                return

            if request is None:
                client_writer.write(RESPONSE_400)
                await client_writer.drain()
                client_writer.close()
                return

            ctx.target_host = request.host
            ctx.target_port = request.port
            log = log.with_context(target=f"{ctx.target_host}:{ctx.target_port}")
            log.info(f"{request.method} {request.uri}")

            # ── Step 4: Authentication ──
            if self._auth and self._auth.is_enabled:
                ctx.transition(ConnState.AUTHENTICATED)
                auth_header = request.headers.get("proxy-authorization")
                success, username = self._auth.authenticate(auth_header)
                if not success:
                    log.warning("Authentication failed")
                    client_writer.write(self._auth.build_407_response())
                    await client_writer.drain()
                    client_writer.close()
                    return
                ctx.authenticated_user = username

            # ── Step 5: IDS/IPS Inspection ──
            if self._inspector:
                ctx.transition(ConnState.INSPECTED)
                action, alerts = await self._inspector.inspect(
                    request, source_ip=ctx.client_addr
                )
                if action == InspectionAction.BLOCK:
                    log.warning(f"Request BLOCKED by IPS ({len(alerts)} alerts)")
                    client_writer.write(RESPONSE_403)
                    await client_writer.drain()
                    client_writer.close()
                    return

            # ── Step 6: Forward / Tunnel ──
            ctx.transition(ConnState.RELAYING)

            if request.is_connect:
                await self._handle_connect(
                    client_reader, client_writer, request, ctx, log
                )
            else:
                await self._handle_http(
                    client_reader, client_writer, request, ctx, log, raw
                )

        except asyncio.CancelledError:
            log.debug("Connection cancelled (shutdown)")
        except Exception as e:
            log.error(f"Unhandled error: {e}", exc_info=True)
        finally:
            ctx.transition(ConnState.CLOSED)
            if self._metrics:
                await self._metrics.adjust_gauge("active_connections", -1)
            log.info(f"Connection closed (duration={ctx.duration:.2f}s)")
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

    async def _handle_connect(
        self, client_reader, client_writer, request, ctx, log
    ) -> None:
        """Handle HTTPS CONNECT tunneling."""
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(ctx.target_host, ctx.target_port),
                timeout=self._timeout,
            )
        except (OSError, asyncio.TimeoutError) as e:
            log.warning(f"Upstream connect failed: {e}")
            client_writer.write(RESPONSE_502)
            await client_writer.drain()
            return

        # Tell client the tunnel is established
        client_writer.write(CONNECT_200)
        await client_writer.drain()

        ctx.is_tls = True
        log.info("CONNECT tunnel established")

        if self._metrics:
            await self._metrics.increment("tls_handshakes")

        # Relay data bidirectionally
        await relay(
            client_reader, client_writer,
            upstream_reader, upstream_writer,
            conn_id=ctx.conn_id,
            metrics=self._metrics,
            buffer_size=self._buffer_size,
        )

    async def _handle_http(
        self, client_reader, client_writer, request, ctx, log, raw_request
    ) -> None:
        """Handle plain HTTP forwarding."""
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(ctx.target_host, ctx.target_port),
                timeout=self._timeout,
            )
        except (OSError, asyncio.TimeoutError) as e:
            log.warning(f"Upstream connect failed: {e}")
            client_writer.write(RESPONSE_502)
            await client_writer.drain()
            return

        # Forward the original request to upstream
        upstream_writer.write(raw_request)
        await upstream_writer.drain()

        # Relay the response back
        try:
            while True:
                data = await asyncio.wait_for(
                    upstream_reader.read(self._buffer_size),
                    timeout=self._timeout,
                )
                if not data:
                    break
                client_writer.write(data)
                await client_writer.drain()
                ctx.bytes_out += len(data)

                if self._metrics:
                    await self._metrics.increment("bytes_transferred", len(data))
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                upstream_writer.close()
                await upstream_writer.wait_closed()
            except Exception:
                pass
