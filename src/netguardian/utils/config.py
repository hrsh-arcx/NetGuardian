"""
netguardian.utils.config — Configuration Loader & Validator

Loads the default YAML configuration, merges it with an optional user-provided
override file, and exposes the result as a typed `ProxyConfig` dataclass.

Hierarchy (later sources override earlier ones):
    1. config/default.yaml       — Built-in defaults
    2. User config file          — Passed via --config CLI flag
    3. CLI argument overrides    — Individual flags (e.g., --port)

"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    max_connections: int = 1024
    connection_timeout: int = 30
    buffer_size: int = 65536


@dataclass
class TLSConfig:
    enabled: bool = True
    cert_dir: str = "certs"
    ca_name: str = "NetGuardian Root CA"
    key_size: int = 2048
    cert_validity_days: int = 365


@dataclass
class IPFilterConfig:
    enabled: bool = True
    default_policy: str = "allow"
    allowlist: List[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])
    blocklist: List[str] = field(default_factory=list)


@dataclass
class RateLimiterConfig:
    enabled: bool = True
    requests_per_second: int = 50
    burst_size: int = 100
    cleanup_interval: int = 60


@dataclass
class AuthConfig:
    enabled: bool = False
    users: Dict[str, str] = field(default_factory=lambda: {"admin": "changeme"})


@dataclass
class InspectionConfig:
    enabled: bool = True
    mode: str = "ids"  # "ids" = alert only, "ips" = alert + block
    signatures_file: str = "config/signatures.yaml"
    max_body_scan_bytes: int = 65536


@dataclass
class LoggingConfig:
    level: str = "INFO"
    console: bool = True
    file: bool = True
    log_dir: str = "logs"
    max_file_size_mb: int = 10
    json_format: bool = True


@dataclass
class MetricsConfig:
    enabled: bool = True
    export_interval: int = 30
    console_table: bool = True
    json_export: bool = True
    json_export_path: str = "logs/metrics.json"


@dataclass
class ProxyConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)
    ip_filter: IPFilterConfig = field(default_factory=IPFilterConfig)
    rate_limiter: RateLimiterConfig = field(default_factory=RateLimiterConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    inspection: InspectionConfig = field(default_factory=InspectionConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)


#  YAML Loading Helpers


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = base.copy()
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _dict_to_config(raw: Dict[str, Any]) -> ProxyConfig:
    #Convert a flat dictionary (from YAML) into the typed ProxyConfig dataclass tree.

    return ProxyConfig(
        server=ServerConfig(**{
            k: v for k, v in raw.get("server", {}).items()
            if k in ServerConfig.__dataclass_fields__
        }),
        tls=TLSConfig(**{
            k: v for k, v in raw.get("tls", {}).items()
            if k in TLSConfig.__dataclass_fields__
        }),
        ip_filter=IPFilterConfig(**{
            k: v for k, v in raw.get("ip_filter", {}).items()
            if k in IPFilterConfig.__dataclass_fields__
        }),
        rate_limiter=RateLimiterConfig(**{
            k: v for k, v in raw.get("rate_limiter", {}).items()
            if k in RateLimiterConfig.__dataclass_fields__
        }),
        auth=AuthConfig(**{
            k: v for k, v in raw.get("auth", {}).items()
            if k in AuthConfig.__dataclass_fields__
        }),
        inspection=InspectionConfig(**{
            k: v for k, v in raw.get("inspection", {}).items()
            if k in InspectionConfig.__dataclass_fields__
        }),
        logging=LoggingConfig(**{
            k: v for k, v in raw.get("logging", {}).items()
            if k in LoggingConfig.__dataclass_fields__
        }),
        metrics=MetricsConfig(**{
            k: v for k, v in raw.get("metrics", {}).items()
            if k in MetricsConfig.__dataclass_fields__
        }),
    )


def _find_default_config() -> Path:

    current = Path(__file__).resolve().parent
    for _ in range(10):  # Safety limit to avoid infinite loop
        candidate = current / "config" / "default.yaml"
        if candidate.exists():
            return candidate
        current = current.parent

    # Fallback: relative to cwd
    fallback = Path("config") / "default.yaml"
    if fallback.exists():
        return fallback

    raise FileNotFoundError(
        "Could not locate config/default.yaml. "
        "Run NetGuardian from the project root directory."
    )


def load_config(
    user_config_path: Optional[str] = None,
    cli_overrides: Optional[Dict[str, Any]] = None,
) -> ProxyConfig:
    #Load and merge configuration from all sources.

    default_path = _find_default_config()
    with open(default_path, "r", encoding="utf-8") as f:
        base_config = yaml.safe_load(f) or {}

    if user_config_path:
        user_path = Path(user_config_path)
        if not user_path.exists():
            raise FileNotFoundError(f"User config file not found: {user_config_path}")
        with open(user_path, "r", encoding="utf-8") as f:
            user_config = yaml.safe_load(f) or {}
        base_config = _deep_merge(base_config, user_config)

    if cli_overrides:
        base_config = _deep_merge(base_config, cli_overrides)

    return _dict_to_config(base_config)


def validate_config(config: ProxyConfig) -> List[str]:
    #Validate a ProxyConfig and return a list of warning/error messages.
    
    issues: List[str] = []

    # Port range check
    if not (1 <= config.server.port <= 65535):
        issues.append(f"Invalid server port: {config.server.port} (must be 1-65535)")

    # IDS mode validation
    if config.inspection.mode not in ("ids", "ips"):
        issues.append(
            f"Invalid inspection mode: '{config.inspection.mode}' "
            f"(must be 'ids' or 'ips')"
        )

    # Log level validation
    valid_levels = {"TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if config.logging.level.upper() not in valid_levels:
        issues.append(
            f"Invalid log level: '{config.logging.level}' "
            f"(must be one of {valid_levels})"
        )

    # Rate limiter sanity
    if config.rate_limiter.enabled:
        if config.rate_limiter.requests_per_second <= 0:
            issues.append("Rate limiter requests_per_second must be > 0")
        if config.rate_limiter.burst_size <= 0:
            issues.append("Rate limiter burst_size must be > 0")

    # Buffer size sanity
    if config.server.buffer_size < 1024:
        issues.append(
            f"Buffer size {config.server.buffer_size} is very small "
            f"(minimum recommended: 1024 bytes)"
        )

    # Default policy validation
    if config.ip_filter.default_policy not in ("allow", "deny"):
        issues.append(
            f"Invalid IP filter default_policy: '{config.ip_filter.default_policy}' "
            f"(must be 'allow' or 'deny')"
        )

    return issues
