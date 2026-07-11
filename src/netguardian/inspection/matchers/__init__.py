"""
netguardian.inspection.matchers — Pluggable Matcher Interface

All matchers inherit from BaseMatcher and implement scan().
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

from netguardian.protocol.http_parser import HttpRequest


@dataclass
class MatchResult:
    """A single match from a matcher."""
    signature_id: str
    signature_name: str
    category: str
    severity: str
    action: str
    matched_text: str
    location: str  # uri, headers, body


class BaseMatcher(ABC):
    """Interface for all inspection matchers."""

    @abstractmethod
    def scan(self, request: HttpRequest) -> List[MatchResult]:
        """Scan a request and return all matches found."""
        ...
