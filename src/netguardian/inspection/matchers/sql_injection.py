"""
netguardian.inspection.matchers.sql_injection — SQLi Heuristic Detector

Specialized SQL injection detector that goes beyond simple regex.
URL-decodes input before scanning, applies multiple heuristic layers,
and assigns a confidence score.
"""

from __future__ import annotations

import re
from typing import List
from urllib.parse import unquote

from netguardian.inspection.matchers import BaseMatcher, MatchResult
from netguardian.protocol.http_parser import HttpRequest

# Pre-compiled heuristic patterns
_PATTERNS = {
    "union_select": re.compile(r"(?i)union\s+(all\s+)?select"),
    "or_bypass": re.compile(r"(?i)(\bor\b\s+\d+\s*=\s*\d+|\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)"),
    "drop_alter": re.compile(r"(?i)\b(drop|alter|truncate)\s+(table|database|column)\b"),
    "stacked_query": re.compile(r"(?i);\s*(select|insert|update|delete|drop|alter|create)\b"),
    "comment_inject": re.compile(r"(--\s|/\*|\*/|#\s)"),
    "tautology": re.compile(r"(?i)'\s*(or|and)\s+'\w+'\s*=\s*'\w+'"),
    "hex_encoding": re.compile(r"(?i)(0x[0-9a-f]+|char\s*\()"),
    "sleep_benchmark": re.compile(r"(?i)(sleep\s*\(|benchmark\s*\()"),
}

_SEVERITY_MAP = {
    "union_select": "high",
    "or_bypass": "high",
    "drop_alter": "critical",
    "stacked_query": "high",
    "comment_inject": "medium",
    "tautology": "high",
    "hex_encoding": "medium",
    "sleep_benchmark": "critical",
}


class SqlInjectionMatcher(BaseMatcher):
    """
    Multi-layer SQL injection detector.
    Scans URI and body after URL-decoding.
    """

    def scan(self, request: HttpRequest) -> List[MatchResult]:
        results = []

        # Scan decoded URI
        decoded_uri = unquote(request.uri)
        results.extend(self._scan_text(decoded_uri, "uri"))

        # Scan decoded body
        if request.body:
            try:
                body_text = unquote(request.body.decode("utf-8", errors="replace"))
                results.extend(self._scan_text(body_text, "body"))
            except Exception:
                pass

        return results

    def _scan_text(self, text: str, location: str) -> List[MatchResult]:
        hits = []
        for name, pattern in _PATTERNS.items():
            match = pattern.search(text)
            if match:
                hits.append(MatchResult(
                    signature_id=f"NG-SQLI-H-{name.upper()}",
                    signature_name=f"SQLi heuristic: {name.replace('_', ' ')}",
                    category="sqli",
                    severity=_SEVERITY_MAP.get(name, "medium"),
                    action="block",
                    matched_text=match.group(0)[:80],
                    location=location,
                ))
        return hits
