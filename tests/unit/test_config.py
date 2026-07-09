"""
Tests for netguardian.utils.config — Configuration Loader & Validator

These tests verify:
    1. Default config loads correctly from YAML
    2. User override files merge properly (deep merge)
    3. CLI overrides take highest priority
    4. Validation catches invalid values
    5. Unknown keys don't crash the loader
    6. Missing files raise proper errors
"""

import os
import tempfile
from pathlib import Path

# pyrefly: ignore [missing-import]
import pytest
import yaml

from netguardian.utils.config import (
    ProxyConfig,
    ServerConfig,
    TLSConfig,
    InspectionConfig,
    LoggingConfig,
    _deep_merge,
    _dict_to_config,
    load_config,
    validate_config,
)


class TestDeepMerge:
    """Verify recursive dictionary merging logic."""

    def test_flat_override(self):
        """Top-level keys in override replace base values."""
        base = {"a": 1, "b": 2}
        override = {"b": 99}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 99}

    def test_nested_merge(self):
        """Nested dicts are merged recursively, not replaced."""
        base = {"server": {"host": "0.0.0.0", "port": 8080}}
        override = {"server": {"port": 9090}}
        result = _deep_merge(base, override)
        # host should survive even though override only has port
        assert result == {"server": {"host": "0.0.0.0", "port": 9090}}

    def test_base_not_mutated(self):
        """The original base dict must not be modified."""
        base = {"a": {"x": 1}}
        override = {"a": {"y": 2}}
        _deep_merge(base, override)
        assert base == {"a": {"x": 1}}  # unchanged

    def test_new_keys_added(self):
        """Keys in override that don't exist in base are added."""
        base = {"a": 1}
        override = {"b": 2}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 2}

    def test_empty_override(self):
        """Empty override returns base unchanged."""
        base = {"a": 1, "b": {"c": 3}}
        result = _deep_merge(base, {})
        assert result == base

    def test_deeply_nested(self):
        """Three levels of nesting merge correctly."""
        base = {"l1": {"l2": {"l3": "original", "keep": True}}}
        override = {"l1": {"l2": {"l3": "changed"}}}
        result = _deep_merge(base, override)
        assert result["l1"]["l2"]["l3"] == "changed"
        assert result["l1"]["l2"]["keep"] is True




class TestDictToConfig:
    """Verify YAML dict → typed dataclass conversion."""

    def test_empty_dict_gives_defaults(self):
        """An empty dict should produce a ProxyConfig with all defaults."""
        config = _dict_to_config({})
        assert config.server.host == "127.0.0.1"
        assert config.server.port == 8080
        assert config.tls.enabled is True
        assert config.inspection.mode == "ids"

    def test_partial_override(self):
        """Only the provided fields should differ from defaults."""
        raw = {"server": {"port": 3128, "host": "0.0.0.0"}}
        config = _dict_to_config(raw)
        assert config.server.port == 3128
        assert config.server.host == "0.0.0.0"
        # Unspecified fields keep defaults
        assert config.server.max_connections == 1024

    def test_unknown_keys_ignored(self):
        """Keys not in the dataclass should not cause errors."""
        raw = {"server": {"port": 8080, "unknown_future_field": True}}
        config = _dict_to_config(raw)  # should not raise
        assert config.server.port == 8080

    def test_all_sections_populated(self):
        """Every config section is accessible on the result."""
        config = _dict_to_config({})
        assert isinstance(config.server, ServerConfig)
        assert isinstance(config.tls, TLSConfig)
        assert isinstance(config.inspection, InspectionConfig)
        assert isinstance(config.logging, LoggingConfig)




class TestLoadConfig:
    """Verify the full load pipeline: default + user file + CLI overrides."""

    def test_load_defaults_only(self):
        """Loading with no overrides gives valid default config."""
        config = load_config()
        assert config.server.port == 8080
        assert config.server.host == "127.0.0.1"

    def test_user_file_override(self, tmp_path: Path):
        """A user YAML file overrides specific defaults."""
        user_yaml = tmp_path / "custom.yaml"
        user_yaml.write_text(yaml.dump({
            "server": {"port": 3128},
            "inspection": {"mode": "ips"},
        }))

        config = load_config(user_config_path=str(user_yaml))
        assert config.server.port == 3128
        assert config.inspection.mode == "ips"
        # Default values should still be present
        assert config.server.host == "127.0.0.1"

    def test_cli_overrides_beat_user_file(self, tmp_path: Path):
        """CLI overrides have highest priority."""
        user_yaml = tmp_path / "custom.yaml"
        user_yaml.write_text(yaml.dump({"server": {"port": 3128}}))

        config = load_config(
            user_config_path=str(user_yaml),
            cli_overrides={"server": {"port": 9999}},
        )
        assert config.server.port == 9999  # CLI wins

    def test_missing_user_file_raises(self):
        """Referencing a nonexistent user config file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="not found"):
            load_config(user_config_path="/nonexistent/config.yaml")

    def test_cli_overrides_only(self):
        """CLI overrides work even without a user file."""
        config = load_config(cli_overrides={"server": {"port": 4444}})
        assert config.server.port == 4444




class TestValidateConfig:
    """Verify that validation catches bad config values."""

    def test_valid_default_config(self):
        """The default config should have zero validation issues."""
        config = load_config()
        issues = validate_config(config)
        assert issues == []

    def test_invalid_port(self):
        """Port outside 1-65535 range is flagged."""
        config = ProxyConfig()
        config.server.port = 99999
        issues = validate_config(config)
        assert any("port" in issue.lower() for issue in issues)

    def test_invalid_inspection_mode(self):
        """Mode other than 'ids' or 'ips' is flagged."""
        config = ProxyConfig()
        config.inspection.mode = "invalid_mode"
        issues = validate_config(config)
        assert any("mode" in issue.lower() for issue in issues)

    def test_invalid_log_level(self):
        """Unrecognized log level is flagged."""
        config = ProxyConfig()
        config.logging.level = "VERBOSE"
        issues = validate_config(config)
        assert any("level" in issue.lower() for issue in issues)

    def test_zero_rate_limit(self):
        """Zero requests_per_second is flagged."""
        config = ProxyConfig()
        config.rate_limiter.requests_per_second = 0
        issues = validate_config(config)
        assert any("requests_per_second" in issue for issue in issues)

    def test_tiny_buffer_size(self):
        """Buffer size below 1024 triggers a warning."""
        config = ProxyConfig()
        config.server.buffer_size = 64
        issues = validate_config(config)
        assert any("buffer" in issue.lower() for issue in issues)

    def test_invalid_default_policy(self):
        """IP filter policy other than allow/deny is flagged."""
        config = ProxyConfig()
        config.ip_filter.default_policy = "maybe"
        issues = validate_config(config)
        assert any("policy" in issue.lower() for issue in issues)
