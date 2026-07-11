"""
netguardian.inspection.engine — Central Inspection Orchestrator

Runs all matchers against an HTTP request, aggregates results,
selects the highest-severity action, and emits alerts/metrics.

Supports two modes:
  - IDS: alert only (log threats, let traffic pass)
  - IPS: alert + block (log threats AND reject the request)
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from netguardian.inspection.actions import AlertRecord, InspectionAction
from netguardian.inspection.matchers import BaseMatcher, MatchResult
from netguardian.inspection.matchers.header_matcher import HeaderMatcher
from netguardian.inspection.matchers.regex_matcher import RegexMatcher
from netguardian.inspection.matchers.sql_injection import SqlInjectionMatcher
from netguardian.inspection.signature_store import SignatureStore
from netguardian.protocol.http_parser import HttpRequest
from netguardian.telemetry.logger import get_logger
from netguardian.telemetry.metrics import MetricsCollector

_log = get_logger("netguardian.inspection.engine")

# Severity ranking for determining which action to take
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class InspectionEngine:
    """
    Central orchestrator. Wires up all matchers and runs them
    against each request in the proxy pipeline.
    """

    def __init__(
        self,
        signature_store: SignatureStore,
        mode: str = "ids",
        metrics: Optional[MetricsCollector] = None,
        max_body_bytes: int = 65536,
    ):
        self._mode = mode  # "ids" or "ips"
        self._metrics = metrics
        self._max_body_bytes = max_body_bytes

        # Build matchers
        self._matchers: List[BaseMatcher] = [
            RegexMatcher(signature_store.get_all()),
            HeaderMatcher(),
            SqlInjectionMatcher(),
        ]

        _log.info(
            f"Inspection engine initialized: mode={mode}, "
            f"signatures={signature_store.count}, matchers={len(self._matchers)}"
        )

    async def inspect(
        self,
        request: HttpRequest,
        source_ip: str = "unknown",
    ) -> Tuple[InspectionAction, List[AlertRecord]]:
        """
        Inspect a request through all matchers.

        Returns:
            (action, alerts) — action is ALLOW, ALERT, or BLOCK.
            In IDS mode, BLOCK matches are downgraded to ALERT.
        """
        # Truncate body for performance
        if len(request.body) > self._max_body_bytes:
            truncated = HttpRequest(
                method=request.method,
                uri=request.uri,
                version=request.version,
                headers=request.headers,
                body=request.body[:self._max_body_bytes],
                raw_request_line=request.raw_request_line,
            )
        else:
            truncated = request

        # Run all matchers
        all_matches: List[MatchResult] = []
        for matcher in self._matchers:
            try:
                matches = matcher.scan(truncated)
                all_matches.extend(matches)
            except Exception as e:
                _log.error(f"Matcher {type(matcher).__name__} failed: {e}")

        if self._metrics:
            await self._metrics.increment("requests_inspected")

        if not all_matches:
            return InspectionAction.ALLOW, []

        # Build alert records and determine action
        alerts: List[AlertRecord] = []
        highest_action = InspectionAction.ALERT
        highest_severity_rank = -1

        for match in all_matches:
            # Determine action for this match
            if match.action == "block" and self._mode == "ips":
                action = InspectionAction.BLOCK
            else:
                action = InspectionAction.ALERT

            alert = AlertRecord.create(
                source_ip=source_ip,
                target_host=request.host,
                signature_id=match.signature_id,
                signature_name=match.signature_name,
                category=match.category,
                severity=match.severity,
                action=action,
                matched_text=match.matched_text,
                location=match.location,
                request_uri=request.uri,
            )
            alerts.append(alert)

            # Log each alert
            _log.warning(
                f"[{action.value.upper()}] {match.signature_id} — {match.signature_name} "
                f"| src={source_ip} target={request.host} "
                f"| matched: {match.matched_text!r} in {match.location}",
                extra={"action": action.value, "signature": match.signature_id},
            )

            # Track highest severity for final decision
            rank = _SEVERITY_RANK.get(match.severity, 0)
            if rank > highest_severity_rank:
                highest_severity_rank = rank
                highest_action = action

        if self._metrics:
            await self._metrics.increment("threats_detected", len(alerts))
            if highest_action == InspectionAction.BLOCK:
                await self._metrics.increment("requests_blocked")

        return highest_action, alerts
