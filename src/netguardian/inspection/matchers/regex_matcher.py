"""
netguardian.inspection.matchers.regex_matcher — Generic Regex Scanner

Runs pre-compiled signature patterns against the appropriate parts of
an HTTP request (URI, headers, body, or all three).
"""

from __future__ import annotations

from typing import List

from netguardian.inspection.matchers import BaseMatcher, MatchResult
from netguardian.inspection.signature_store import Signature
from netguardian.protocol.http_parser import HttpRequest


class RegexMatcher(BaseMatcher):
    """Scans requests using pre-compiled regex signatures."""

    def __init__(self, signatures: List[Signature]):
        self._signatures = signatures

    def scan(self, request: HttpRequest) -> List[MatchResult]:
        results = []
        for sig in self._signatures:
            matches = self._match_signature(sig, request)
            results.extend(matches)
        return results

    def _match_signature(self, sig: Signature, req: HttpRequest) -> List[MatchResult]:
        hits = []
        targets = self._get_targets(sig.target, req)

        for location, text in targets:
            match = sig.compiled.search(text)
            if match:
                hits.append(MatchResult(
                    signature_id=sig.id,
                    signature_name=sig.name,
                    category=sig.category,
                    severity=sig.severity,
                    action=sig.action,
                    matched_text=match.group(0)[:100],  # truncate long matches
                    location=location,
                ))
        return hits

    @staticmethod
    def _get_targets(target: str, req: HttpRequest) -> List[tuple]:
        """Return (location_name, text) pairs to scan based on signature target."""
        targets = []
        if target in ("uri", "any"):
            targets.append(("uri", req.decoded_uri))
        if target in ("headers", "any"):
            header_str = "\n".join(f"{k}: {v}" for k, v in req.headers.items())
            targets.append(("headers", header_str))
        if target in ("body", "any"):
            try:
                body_text = req.body.decode("utf-8", errors="replace")
            except Exception:
                body_text = ""
            targets.append(("body", body_text))
        return targets
