"""
netguardian.inspection.signature_store — Signature Database Loader

Loads IDS signatures from config/signatures.yaml, pre-compiles regex
patterns at startup, and indexes them by category for fast lookup.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

import yaml

from netguardian.telemetry.logger import get_logger

_log = get_logger("netguardian.inspection.signatures")


@dataclass
class Signature:
    """A single IDS detection rule."""
    id: str
    name: str
    category: str           # sqli, xss, traversal, cmdi, recon
    severity: str            # low, medium, high, critical
    action: str              # alert, block
    target: str              # uri, headers, body, any
    pattern: str             # raw regex string
    compiled: re.Pattern     # pre-compiled for performance


class SignatureStore:
    """
    Loads, validates, and indexes signatures from YAML.
    Pre-compiles all regex patterns once at startup so the hot path
    (matching during request inspection) is as fast as possible.
    """

    VALID_SEVERITIES = {"low", "medium", "high", "critical"}
    VALID_ACTIONS = {"alert", "block"}
    VALID_TARGETS = {"uri", "headers", "body", "any"}

    def __init__(self):
        self._signatures: List[Signature] = []
        self._by_category: Dict[str, List[Signature]] = {}
        self._by_id: Dict[str, Signature] = {}

    def load_from_file(self, path: str) -> int:
        """Load signatures from a YAML file. Returns count loaded."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "signatures" not in data:
            _log.warning(f"No signatures found in {path}")
            return 0

        count = 0
        for entry in data["signatures"]:
            sig = self._parse_entry(entry)
            if sig:
                self._signatures.append(sig)
                self._by_id[sig.id] = sig
                self._by_category.setdefault(sig.category, []).append(sig)
                count += 1

        _log.info(f"Loaded {count} signatures from {path}")
        return count

    def _parse_entry(self, entry: dict) -> Optional[Signature]:
        """Validate and compile a single signature entry."""
        required = ("id", "name", "category", "severity", "action", "target", "pattern")
        for key in required:
            if key not in entry:
                _log.warning(f"Signature missing field '{key}': {entry.get('id', '?')}")
                return None

        if entry["severity"] not in self.VALID_SEVERITIES:
            _log.warning(f"Invalid severity in {entry['id']}: {entry['severity']}")
            return None

        if entry["action"] not in self.VALID_ACTIONS:
            _log.warning(f"Invalid action in {entry['id']}: {entry['action']}")
            return None

        if entry["target"] not in self.VALID_TARGETS:
            _log.warning(f"Invalid target in {entry['id']}: {entry['target']}")
            return None

        try:
            compiled = re.compile(entry["pattern"])
        except re.error as e:
            _log.warning(f"Bad regex in {entry['id']}: {e}")
            return None

        return Signature(
            id=entry["id"],
            name=entry["name"],
            category=entry["category"],
            severity=entry["severity"],
            action=entry["action"],
            target=entry["target"],
            pattern=entry["pattern"],
            compiled=compiled,
        )

    def get_all(self) -> List[Signature]:
        return list(self._signatures)

    def get_by_category(self, category: str) -> List[Signature]:
        return self._by_category.get(category, [])

    def get_by_id(self, sig_id: str) -> Optional[Signature]:
        return self._by_id.get(sig_id)

    @property
    def count(self) -> int:
        return len(self._signatures)

    @property
    def categories(self) -> List[str]:
        return list(self._by_category.keys())
