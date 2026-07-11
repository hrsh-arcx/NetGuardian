"""
netguardian.inspection.matchers.header_matcher — HTTP Header Anomaly Detector

Checks for suspicious header patterns: missing Host, suspicious User-Agent,
oversized headers, and header injection attempts.
"""

from __future__ import annotations

from typing import List

from netguardian.inspection.matchers import BaseMatcher, MatchResult
from netguardian.protocol.http_parser import HttpRequest


class HeaderMatcher(BaseMatcher):
    """Detects HTTP header anomalies without relying on regex signatures."""

    MAX_HEADER_VALUE_LEN = 4096

    def scan(self, request: HttpRequest) -> List[MatchResult]:
        results = []

        # Missing Host header
        if "host" not in request.headers and not request.is_connect:
            results.append(MatchResult(
                signature_id="NG-HDR-001",
                signature_name="Missing Host header",
                category="recon",
                severity="medium",
                action="alert",
                matched_text="(no Host header)",
                location="headers",
            ))

        # Missing or empty User-Agent
        ua = request.headers.get("user-agent", "")
        if not ua.strip():
            results.append(MatchResult(
                signature_id="NG-HDR-002",
                signature_name="Missing User-Agent header",
                category="recon",
                severity="low",
                action="alert",
                matched_text="(empty User-Agent)",
                location="headers",
            ))

        # Header injection attempt (CRLF in values)
        for key, value in request.headers.items():
            if "\r" in value or "\n" in value:
                results.append(MatchResult(
                    signature_id="NG-HDR-003",
                    signature_name="Header injection (CRLF in value)",
                    category="cmdi",
                    severity="high",
                    action="block",
                    matched_text=f"{key}: (contains CRLF)",
                    location="headers",
                ))

        # Oversized header values
        for key, value in request.headers.items():
            if len(value) > self.MAX_HEADER_VALUE_LEN:
                results.append(MatchResult(
                    signature_id="NG-HDR-004",
                    signature_name="Oversized header value",
                    category="recon",
                    severity="medium",
                    action="alert",
                    matched_text=f"{key}: ({len(value)} bytes)",
                    location="headers",
                ))

        return results
