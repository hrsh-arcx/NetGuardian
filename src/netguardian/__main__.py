"""
netguardian.__main__ — Application Entry Point

Initializes all subsystems in order and starts the async proxy server.
Run with: python -m netguardian [options]
"""

from __future__ import annotations

import asyncio
import sys

from netguardian.cli import parse_args
from netguardian.core.proxy_handler import ProxyHandler
from netguardian.core.server import ProxyServer
from netguardian.inspection.engine import InspectionEngine
from netguardian.inspection.signature_store import SignatureStore
from netguardian.security.auth import ProxyAuthenticator
from netguardian.security.ip_filter import IPFilter
from netguardian.security.rate_limiter import RateLimiter
from netguardian.security.tls_manager import CertificateManager
from netguardian.telemetry.logger import setup_logging, get_logger
from netguardian.telemetry.metrics import MetricsCollector
from netguardian.telemetry.stats_exporter import StatsExporter
from netguardian.utils.graceful_shutdown import GracefulShutdown


def main() -> None:
    """Main entry point."""
    config, args = parse_args()

    # ── 1. Logging ──
    setup_logging(
        level=config.logging.level,
        console_enabled=config.logging.console,
        file_enabled=config.logging.file,
        log_dir=config.logging.log_dir,
        max_file_size_mb=config.logging.max_file_size_mb,
        json_format=config.logging.json_format,
    )
    log = get_logger("netguardian.main")
    log.info("NetGuardian starting up...")

    # ── 2. Metrics ──
    metrics = MetricsCollector() if config.metrics.enabled else None

    # ── 3. Graceful Shutdown ──
    shutdown = GracefulShutdown(drain_timeout=config.server.connection_timeout)

    # ── 4. Security: IP Filter ──
    ip_filter = None
    if config.ip_filter.enabled:
        ip_filter = IPFilter(
            allowlist=config.ip_filter.allowlist,
            blocklist=config.ip_filter.blocklist,
            default_policy=config.ip_filter.default_policy,
        )

    # ── 5. Security: Rate Limiter ──
    rate_limiter = None
    if config.rate_limiter.enabled:
        rate_limiter = RateLimiter(
            requests_per_second=config.rate_limiter.requests_per_second,
            burst_size=config.rate_limiter.burst_size,
            cleanup_interval=config.rate_limiter.cleanup_interval,
        )

    # ── 6. Security: Authentication ──
    authenticator = None
    if config.auth.enabled:
        authenticator = ProxyAuthenticator(
            users=config.auth.users,
            enabled=True,
        )

    # ── 7. Security: TLS Manager ──
    tls_manager = None
    if config.tls.enabled:
        tls_manager = CertificateManager(
            cert_dir=config.tls.cert_dir,
            ca_name=config.tls.ca_name,
            key_size=config.tls.key_size,
        )

    # ── 8. Inspection Engine ──
    inspection_engine = None
    if config.inspection.enabled:
        sig_store = SignatureStore()
        try:
            sig_store.load_from_file(config.inspection.signatures_file)
        except FileNotFoundError:
            log.warning(
                f"Signatures file not found: {config.inspection.signatures_file}. "
                "IDS running with zero signatures."
            )
        inspection_engine = InspectionEngine(
            signature_store=sig_store,
            mode=config.inspection.mode,
            metrics=metrics,
            max_body_bytes=config.inspection.max_body_scan_bytes,
        )

    # ── 9. Proxy Handler ──
    handler = ProxyHandler(
        ip_filter=ip_filter,
        rate_limiter=rate_limiter,
        authenticator=authenticator,
        inspection_engine=inspection_engine,
        tls_manager=tls_manager,
        metrics=metrics,
        connection_timeout=config.server.connection_timeout,
        buffer_size=config.server.buffer_size,
    )

    # ── 10. Server ──
    server = ProxyServer(
        handler=handler,
        host=config.server.host,
        port=config.server.port,
        max_connections=config.server.max_connections,
        shutdown=shutdown,
        metrics=metrics,
    )

    # ── Run ──
    async def _run() -> None:
        # Start background tasks
        if rate_limiter:
            await rate_limiter.start_cleanup()

        stats_exporter = None
        if metrics and config.metrics.enabled:
            stats_exporter = StatsExporter(
                metrics=metrics,
                interval=config.metrics.export_interval,
                console_table=config.metrics.console_table,
                json_export=config.metrics.json_export,
                json_path=config.metrics.json_export_path,
            )
            await stats_exporter.start()
            shutdown.add_cleanup_callback(stats_exporter.stop)

        if rate_limiter:
            shutdown.add_cleanup_callback(rate_limiter.stop_cleanup)

        await server.start()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass

    log.info("NetGuardian stopped.")


if __name__ == "__main__":
    main()
