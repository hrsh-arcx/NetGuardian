"""
netguardian.cli — Command-Line Interface

Parses CLI arguments, loads configuration, and merges CLI overrides
into the config hierarchy.
"""

from __future__ import annotations

import argparse
from typing import Dict, Optional, Tuple, Any

from netguardian import __version__
from netguardian.utils.config import ProxyConfig, load_config, validate_config
from netguardian.telemetry.logger import get_logger

_log = get_logger("netguardian.cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netguardian",
        description="NetGuardian — High-Performance Infrastructure Proxy",
    )
    parser.add_argument(
        "--version", action="version", version=f"NetGuardian {__version__}"
    )
    parser.add_argument(
        "--config", "-c", type=str, default=None,
        help="Path to a custom YAML configuration file",
    )
    parser.add_argument(
        "--host", type=str, default=None,
        help="Listen address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port", "-p", type=int, default=None,
        help="Listen port (default: 8080)",
    )
    parser.add_argument(
        "--mode", type=str, choices=["ids", "ips"], default=None,
        help="Inspection mode: ids=alert only, ips=alert+block",
    )
    parser.add_argument(
        "--log-level", type=str, default=None,
        help="Logging level: TRACE, DEBUG, INFO, WARNING, ERROR",
    )
    parser.add_argument(
        "--no-tls", action="store_true",
        help="Disable TLS interception",
    )
    parser.add_argument(
        "--no-inspection", action="store_true",
        help="Disable IDS/IPS inspection engine",
    )
    parser.add_argument(
        "--stats-interval", type=int, default=None,
        help="Seconds between stats reports (default: 30)",
    )
    return parser


def parse_args(argv=None) -> Tuple[ProxyConfig, argparse.Namespace]:
    """
    Parse CLI arguments, load config, merge overrides.
    Returns (config, raw_args).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    # Build CLI overrides dict matching the YAML structure
    cli_overrides: Dict[str, Any] = {}

    if args.host:
        cli_overrides.setdefault("server", {})["host"] = args.host
    if args.port:
        cli_overrides.setdefault("server", {})["port"] = args.port
    if args.mode:
        cli_overrides.setdefault("inspection", {})["mode"] = args.mode
    if args.log_level:
        cli_overrides.setdefault("logging", {})["level"] = args.log_level
    if args.no_tls:
        cli_overrides.setdefault("tls", {})["enabled"] = False
    if args.no_inspection:
        cli_overrides.setdefault("inspection", {})["enabled"] = False
    if args.stats_interval:
        cli_overrides.setdefault("metrics", {})["export_interval"] = args.stats_interval

    config = load_config(
        user_config_path=args.config,
        cli_overrides=cli_overrides if cli_overrides else None,
    )

    # Validate
    issues = validate_config(config)
    for issue in issues:
        _log.warning(f"Config issue: {issue}")

    return config, args
